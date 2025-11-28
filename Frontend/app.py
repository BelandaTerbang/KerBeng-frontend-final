from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file
import subprocess
import os
import sys
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
import threading
import queue
from urllib.parse import unquote
from dotenv import load_dotenv
load_dotenv()


app = Flask(__name__, template_folder='templates')
ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASS = os.getenv("ADMIN_PASS")
app.secret_key = os.getenv("SECRET_KEY")


# --- Konfigurasi waktu hidup session ---
app.permanent_session_lifetime = timedelta(minutes=30)

# --- Terapkan session permanent di setiap request ---
@app.before_request
def make_session_permanent():
    session.permanent = True

# Direktori untuk menyimpan data jobs
JOBS_DIR = Path('jobs')
JOBS_DIR.mkdir(exist_ok=True)

# Queue untuk sequential execution (antrian job)
job_queue = queue.Queue()

# In-memory storage untuk active jobs
active_jobs = {}
current_running_job = None

# ====================================================================
# Helper Functions
# ====================================================================

def load_all_jobs():
    """Load semua jobs dari folder jobs/"""
    jobs = []
    for job_file in JOBS_DIR.glob('*.json'):
        try:
            with open(job_file, 'r', encoding='utf-8') as f:
                job_data = json.load(f)
                # tambahkan ID berdasarkan nama file JSON
                job_data.setdefault('id', job_file.stem)
                jobs.append(job_data)
        except Exception as e:
            print(f"Error loading {job_file}: {e}")
    # Sort by created_at, newest first
    jobs.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return jobs

def save_job(job_data):
    """Simpan job data ke file JSON"""
    job_file = JOBS_DIR / f"{job_data['job_id']}.json"
    with open(job_file, 'w', encoding='utf-8') as f:
        json.dump(job_data, f, indent=2, ensure_ascii=False)

def get_job(job_id):
    """Get job by ID"""
    job_file = JOBS_DIR / f"{job_id}.json"
    if job_file.exists():
        with open(job_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None

def update_job_status(job_id, status, **kwargs):
    """Update job status"""
    job = get_job(job_id)
    if job:
        job['status'] = status
        job.update(kwargs)
        save_job(job)

# ====================================================================
# Routes - Pages
# ====================================================================

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session.clear()  # Reset session lama dulu

        username = request.form.get('username')
        password = request.form.get('password')

        #  Validasi menggunakan .env
        if username == ADMIN_USER and password == ADMIN_PASS:
            # ✔ Jika benar → lanjutkan format session yang kamu pakai
            session['username'] = username
            session['authenticated'] = True
            session['user'] = username  # Minimal tambahan, tetap ada

            print(f"✅ Login berhasil untuk user: {username}")
            print(f"Session keys sekarang: {list(session.keys())}")

            return redirect(url_for('dashboard'))

        #Jika salah → kembali ke login (atau bisa kasih error)
        return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Load semua jobs
    all_jobs = load_all_jobs()
    # Hitung statistik
    total_projects = len(all_jobs)
    completed = len([j for j in all_jobs if j.get('status') == 'completed'])
    running = len([j for j in all_jobs if j.get('status') == 'running'])
    errors = len([j for j in all_jobs if j.get('status') == 'failed'])
    # Ambil 10 jobs terbaru untuk tabel
    recent_jobs = all_jobs[:10]
    # Ambil running jobs untuk progress table
    running_jobs = [j for j in all_jobs if j.get('status') == 'running']
    # Ambil queued jobs
    queued_jobs = [j for j in all_jobs if j.get('status') == 'queued']
    # Debug singkat: tampilkan session keys / username yang ada sebelum render
    print(f"[dashboard] session keys: {list(session.keys())}, username: {session.get('username')}")

    return render_template(
        'dashboard.html',
        breadcrumb=[('Dashboard', None)],
        active_page='dashboard',
        stats={
            'total': total_projects,
            'completed': completed,
            'running': running,
            'errors': errors
        },
        recent_jobs=recent_jobs,
        running_jobs=running_jobs + queued_jobs,  # Gabungkan running dan queued
        username=session.get('username')  # <-- tambahan minimal agar template tidak error
    )



@app.route('/scan_vulnerability', methods=['GET'])
def scan_vulnerability():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Ambil draft dari session (jika ada)
    form_data = session.get('scan_data', {})

    return render_template(
        'scan_vulnerability.html',
        breadcrumb=[('Scan Vulnerability', None)],
        active_page='project',
        form_data=form_data
    )

@app.route('/select_cve')
def select_cve():
    if 'user' not in session:
        return redirect(url_for('login'))

    """Halaman 2: Select CVE dari hasil scan"""
    return render_template(
        'select_cve.html',
        breadcrumb=[
            ('Scan Vulnerability', url_for('scan_vulnerability')),
            ('Select CVE', None)
        ],
        active_page='project'
    )


@app.route('/api/scan-vulnerability', methods=['POST'])
def api_scan_vulnerability():
    """
    API Endpoint untuk scan vulnerability

    🔌 BACKEND INTEGRATION POINT 1: Vulnerability Scanner

    INPUT dari frontend:
    {
        "project_name": "My Project",
        "username": "John",
        "description": "Test scan",
        "targets": ["192.168.1.10", "192.168.1.20"]
    }

    OUTPUT yang diharapkan ke frontend:
    {
        "status": "success",
        "message": "Scan completed",
        "results": [
            {
                "id": "CVE12_2122",
                "name": "MySQL Auth Bypass",
                "description": "Authentication bypass in MySQL",
                "severity": "High",
                "cvss": "7.5",
                "target": "192.168.1.10"
            },
            {
                "id": "CVE22_46169",
                "name": "Cacti RCE",
                "description": "Remote Code Execution in Cacti",
                "severity": "Critical",
                "cvss": "9.8",
                "target": "192.168.1.10"
            }
        ]
    }

    TODO Backend Team:
    1. Terima data targets dari request
    2. Jalankan vulnerability scanner (nmap, nikto, dll)
    3. Parse hasil scan
    4. Return daftar CVE yang terdeteksi dalam format di atas
    """
    data = request.get_json()
    targets = data.get('targets', [])
    project_name = data.get('project_name')

    if not targets:
        return jsonify({
            "status": "error",
            "message": "No targets provided"
        }), 400

    try:
        # ============================================================
        # 🔌 BACKEND: PANGGIL SCRIPT VULNERABILITY SCANNER DI SINI
        # ============================================================
        # Contoh:
        # from scanner import VulnerabilityScanner
        # scanner = VulnerabilityScanner()
        # scan_results = scanner.scan(targets)

        # SEMENTARA: Return dummy data
        # TODO: Replace dengan hasil scan sesungguhnya dari backend
        # --- SIMPAN DRAFT KE SESSION supaya bisa prefill ketika user balik lewat breadcrumb ---
        session['scan_data'] = {
            'project_name': project_name,
            'username': data.get('username'),
            'description': data.get('description'),
            'enableTarget2': len(targets) > 1,
            'targets': targets
        }
    except Exception:
        # Jangan gagal total kalau session bermasalah; lanjutkan scan
        pass

    try:
        # === panggil scanner sebenarnya di sini ===
        # sementara return dummy:
        dummy_results = [
            {
                "id": "CVE12_2122",
                "name": "MySQL Auth Bypass",
                "description": "Authentication bypass vulnerability in MySQL",
                "severity": "High",
                "cvss": "7.5",
                "target": targets[0] if targets else "unknown"
            },
            {
                "id": "CVE22_46169",
                "name": "Cacti RCE",
                "description": "Remote Code Execution in Cacti",
                "severity": "Critical",
                "cvss": "9.8",
                "target": targets[0] if targets else "unknown"
            }
        ]

        return jsonify({
            "status": "success",
            "message": f"Scan completed for {len(targets)} target(s)",
            "results": dummy_results
        })

    except Exception as e:
        return jsonify({"status": "error", "message": f"Scan failed: {str(e)}"}), 500

@app.route('/api/save-scan-draft', methods=['POST'])
def api_save_scan_draft():
    data = request.get_json() or {}
    session['scan_data'] = {
        'project_name': data.get('project_name', ''),
        'username': data.get('username', ''),
        'description': data.get('description', ''),
        'enableTarget2': data.get('enableTarget2', False),
        'targets': data.get('targets', [])
    }
    return jsonify({"status": "success", "message": "Draft saved"})

# ====================================================================
# CATATAN UNTUK INTEGRASI BACKEND:
# ====================================================================
"""
File struktur yang perlu dibuat:

1. templates/scan_vulnerability.html  (Halaman 1: Scan)
2. templates/select_cve.html          (Halaman 2: Select CVE)

Backend Integration Points:

📍 POINT 1: /api/scan-vulnerability (di atas)
   - Input: List of targets
   - Process: Run vulnerability scanner
   - Output: List of detected CVEs with details

📍 POINT 2: /api/start-pentest (sudah ada di app.py)
   - Input: Project info + targets with selected CVEs
   - Process: Start pentest jobs
   - Output: Job IDs and status

Cara Update Navigation:

Di templates/components/sidebar.html, ubah link "Projects" ke:
<a href="{{ url_for('scan_vulnerability') }}">
   <i data-lucide="folder-open"></i>
   <span>Projects</span>
</a>

Di templates/dashboard.html, ubah button "Create Pentest" ke:
<a href="{{ url_for('scan_vulnerability') }}">
   <i data-lucide="plus-circle"></i>
   Create Pentest
</a>
"""

@app.route('/reports')
def reports():
    if 'user' not in session:
        return redirect(url_for('login'))

    # Load completed jobs
    all_jobs = load_all_jobs()
    completed_jobs = [j for j in all_jobs if j.get('status') in ['completed', 'failed']]
    return render_template(
        'reports.html',
        breadcrumb=[
            ('Reports', None)
        ],
        active_page='reports',
        jobs=completed_jobs
    )

@app.route('/logout')
def logout():
    session.clear()
    response = render_template('logout.html')
    return response

# ====================================================================
# API Endpoints
# ====================================================================

@app.route('/api/start-pentest', methods=['POST'])
def start_pentest_api():
    """Start pentest job(s) - SEQUENTIAL execution (satu per satu)"""
    data = request.get_json()
    project_name = data.get('project_name', 'Unnamed Project')
    username = data.get('username', session.get('username', 'Anonymous'))
    description = data.get('description', '')

    # Support format lama (single target) dan baru (multiple targets)
    targets = data.get('targets', [])

    # Jika format lama (target_ip & cve_module langsung), convert ke array
    if not targets and data.get('target_ip'):
        targets = [{
            'target_ip': data.get('target_ip'),
            'cve_module': data.get('cve_module')
        }]

    if not targets or len(targets) == 0:
        return jsonify({
            "status": "error",
            "message": "At least one target is required"
        }), 400

    # Validasi maksimal 2 targets
    if len(targets) > 2:
        return jsonify({
            "status": "error",
            "message": "Maximum 2 pentests at once"
        }), 400

    created_jobs = []

    # Buat job untuk setiap target
    for idx, target in enumerate(targets):
        target_ip = target.get('target_ip', '').strip()
        cve_module = target.get('cve_module', '').strip()

        if not target_ip or not cve_module:
            continue

        # Generate unique job ID
        job_id = f"job_{int(time.time())}_{idx}_{os.urandom(3).hex()}"

        # Nama project - tambahkan suffix jika lebih dari 1 target
        if len(targets) > 1:
            job_project_name = f"{project_name} - Target {idx + 1}"
        else:
            job_project_name = project_name

        # Create job data dengan status 'queued' dulu
        job_data = {
            'job_id': job_id,
            'project_name': job_project_name,
            'username': username,
            'description': description,
            'target_ip': target_ip,
            'cve_module': cve_module,
            'status': 'queued',  # Status awal: queued
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'progress': 0,
            'pid': None,
            'queue_position': idx + 1
        }

        # Simpan ke file
        save_job(job_data)

        # Masukkan ke queue
        job_queue.put(job_data)

        created_jobs.append(job_data)

    if not created_jobs:
        return jsonify({
            "status": "error",
            "message": "No valid targets provided"
        }), 400

    return jsonify({
        "status": "success",
        "message": f"{len(created_jobs)} pentest(s) queued successfully. They will run sequentially.",
        "jobs": created_jobs
    })

@app.route('/api/jobs')
def get_jobs_api():
    """Get all jobs as JSON"""
    jobs = load_all_jobs()
    return jsonify({"jobs": jobs})

@app.route('/api/jobs/<job_id>')
def get_job_api(job_id):
    """Get specific job by ID"""
    job = get_job(job_id)
    if job:
        return jsonify(job)
    return jsonify({"error": "Job not found"}), 404

#----------------------------------------------------------------------------
# TAMBAHAN BARU ROUTE DOWNLOAD
#----------------------------------------------------------------------------
@app.route('/api/reports/<project_name>/download')
def download_report(project_name):
    """
    Download PDF report berdasarkan nama project.
    File report disimpan di folder 'reports' atau di direktori JOBS_DIR.
    """
    project_name = unquote(project_name).strip()

    # Lokasi folder report
    base_dir = os.path.dirname(os.path.abspath(__file__))
    report_dir = os.path.join(base_dir, "reports")

    # Pastikan folder report ada
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

    # Format nama file report yang diharapkan
    expected_report = f"{project_name}_Report.pdf"
    report_path = os.path.join(report_dir, expected_report)

    # Jika file tidak ada, coba fallback nama generik (misal Pentesting_Report.pdf)
    if not os.path.exists(report_path):
        generic_path = os.path.join(report_dir, "Pentesting_Report.pdf")
        if os.path.exists(generic_path):
            report_path = generic_path
        else:
            return jsonify({
                "error": f"Report for '{project_name}' not found."
            }), 404

    # Return file PDF untuk diunduh
    try:
        return send_file(
            report_path,
            as_attachment=True,
            download_name=f"{project_name}_Report.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        return jsonify({
            "error": f"Failed to download report: {str(e)}"
        }), 500



@app.route('/api/reports/<project_name>/view')
def view_report(project_name):
    """
    Menampilkan PDF inline, dan mengatur title tab dengan nama file PDF.
    """
    project_name = unquote(project_name).strip()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    report_dir = os.path.join(base_dir, "reports")

    expected_report = f"{project_name}_Report.pdf"
    report_path = os.path.join(report_dir, expected_report)

    # Fallback jika file tidak ditemukan
    if not os.path.exists(report_path):
        expected_report = "Pentesting_Report.pdf"
        report_path = os.path.join(report_dir, expected_report)

        if not os.path.exists(report_path):
            return jsonify({
                "error": f"Report for '{project_name}' not found."
            }), 404

    try:
        return send_file(
            report_path,
            as_attachment=False,           # tetap inline
            download_name=expected_report, # ⚠️ TAB TITLE BERDASARKAN INI
            mimetype='application/pdf'
        )
    except Exception as e:
        return jsonify({
            "error": f"Failed to open report: {str(e)}"
        }), 500



@app.route("/htmx/reports-table")
def htmx_reports_table():
    all_jobs = load_all_jobs()  # ambil semua, bukan hanya [:10]
    search = request.args.get("search", "").lower()

    # Filter berdasarkan pencarian
    if search:
        all_jobs = [job for job in all_jobs if search in job["project_name"].lower()]

    # Sorting opsional
    sort_by = request.args.get("sort_by", "created_at")
    order = request.args.get("order", "desc")
    reverse = (order == "desc")
    all_jobs.sort(key=lambda x: x.get(sort_by, ""), reverse=reverse)

    return render_template("partials/reports_table.html", jobs=all_jobs)

# ====================================================================
# htmx Endpoints - Untuk real-time updates
# ====================================================================

@app.route('/htmx/stats')
def htmx_stats():
    """Return stats cards HTML (untuk auto-refresh)"""
    all_jobs = load_all_jobs()
    stats = {
        'total': len(all_jobs),
        'completed': len([j for j in all_jobs if j.get('status') == 'completed']),
        'running': len([j for j in all_jobs if j.get('status') in ['running', 'queued']]),
        'errors': len([j for j in all_jobs if j.get('status') == 'failed'])
    }
    return render_template('partials/stats_cards.html', stats=stats)

@app.route('/htmx/jobs-table')
def htmx_jobs_table():
    """Return jobs table HTML (untuk auto-refresh + search + sort)"""
    query = request.args.get("search", "").lower().strip()
    sort_by = request.args.get('sort_by', 'created_at')
    order = request.args.get('order', 'desc')  # asc / desc

    # Ambil semua jobs
    all_jobs = load_all_jobs()

    # Filter berdasarkan search query
    if query:
        all_jobs = [
            j for j in all_jobs
            if query in j.get("project_name", "").lower()
            or query in j.get("username", "").lower()
            or query in j.get("target_ip", "").lower()
            or query in j.get("status", "").lower()
        ]

    # Sorting — gunakan recent_jobs (bukan all_jobs[:10] dulu)
    reverse = (order == 'desc')

    try:
        all_jobs.sort(
            key=lambda x: str(x.get(sort_by, '')).lower(),
            reverse=reverse
        )
    except Exception as e:
        print(f"Sort error: {e}")

    # Setelah disort baru ambil 10 terbaru
    recent_jobs = all_jobs[:10]

    # Kirim data sort agar icon panah bisa berubah
    return render_template(
        'partials/jobs_table.html',
        jobs=recent_jobs,
        sort_by=sort_by,
        order=order
    )

@app.route('/delete-job', methods=['DELETE'])
def delete_job():
    data = request.get_json(silent=True) or {}
    job_id = (
        request.form.get("job_id")
        or request.args.get("job_id")
        or data.get("job_id")
    )
    project_name = (
        request.form.get("project_name")
        or request.args.get("project_name")
        or data.get("project_name")
        or "Unknown Project"
    )

    if not job_id:
        return render_template(
            "partials/alert.html",
            type="error",
            title="Delete Failed",
            message="Job ID not provided."
        ), 400

    deleted = False
    for job_file in JOBS_DIR.glob("*.json"):
        try:
            with open(job_file, "r", encoding="utf-8") as f:
                job_data = json.load(f)

            if str(job_data.get("job_id")) == str(job_id):
                print(f"Deleting job file: {job_file.name}")
                f.close()

                # --- Hapus file JSON ---
                for i in range(3):
                    try:
                        os.remove(job_file)
                        deleted = True
                        break
                    except PermissionError:
                        time.sleep(0.5)

                # --- Hapus file log (jika ada) ---
                # misalnya nama log berdasarkan job_id atau project_name
                log_patterns = [
                    f"{job_id}.log",
                    f"{project_name}.log"
                ]
                for log_pattern in log_patterns:
                    for log_file in JOBS_DIR.glob(log_pattern):
                        try:
                            print(f"Deleting log file: {log_file.name}")
                            os.remove(log_file)
                        except Exception as e:
                            print(f"Error deleting log file {log_file}: {e}")

                break  # berhenti setelah menemukan dan hapus job

        except Exception as e:
            print(f"Error deleting {job_file}: {e}")

    if deleted:
        return render_template(
            "partials/alert.html",
            type="success",
            title="Job Deleted",
            message=f"Job <b>{project_name}</b> was successfully deleted (including logs)."
        )
    else:
        return render_template(
            "partials/alert.html",
            type="error",
            title="Delete Failed",
            message=f"Job <b>{project_name}</b> not found."
        ), 404

    
@app.route('/partials/confirm-delete-modal')
def confirm_delete_modal():
    job_id = request.args.get("job_id")
    project_name = request.args.get("project_name")
    return render_template("partials/confirm_delete_modal.html",
                           job_id=job_id,
                           project_name=project_name)

@app.route('/partials/confirm-cancel-modal')
def confirm_cancel_modal():
    job_id = request.args.get("job_id")
    project_name = request.args.get("project_name")
    return render_template("partials/confirm_cancel_modal.html",
                           job_id=job_id,
                           project_name=project_name)

@app.route('/partials/confirm-remove-modal')
def confirm_remove_queue_modal():
    job_id = request.args.get("job_id")
    project_name = request.args.get("project_name")
    return render_template("partials/confirm_remove_modal.html",
                           job_id=job_id,
                           project_name=project_name)


@app.route('/htmx/progress-table')
def htmx_progress_table():
    """Return jobs table HTML (untuk auto-refresh + search + sort)"""
    query = (
        request.args.get("progress_search")
        or request.args.get("search")
        or ""
    ).lower().strip()

    sort_by = request.args.get("sort_by", "created_at")
    order = request.args.get("order", "desc")

    all_jobs = load_all_jobs()

    # Filter berdasarkan search query
    if query:
        all_jobs = [
            j for j in all_jobs
            if query in j.get("project_name", "").lower()
            or query in j.get("target_ip", "").lower()
        ]

    running_jobs = [j for j in all_jobs if j.get("status") in ["running", "queued"]]
    reverse = (order == "desc")
    running_jobs.sort(key=lambda x: x.get(sort_by, ""), reverse=reverse)

    return render_template(
        "partials/progress_table.html",
        jobs=running_jobs,
        sort_by=sort_by,
        order=order
    )

@app.route('/cancel-job', methods=['POST'])
def cancel_job():
    data = request.get_json(silent=True) or {}
    job_id = (
        request.form.get("job_id")
        or request.args.get("job_id")
        or data.get("job_id")
    )
    project_name = (
        request.form.get("project_name")
        or request.args.get("project_name")
        or data.get("project_name")
        or "Unknown Project"
    )

    if not job_id:
        return render_template(
            "partials/alert.html",
            type="error",
            title="Cancel Failed",
            message="Job ID not provided."
        ), 400

    updated = False
    for job_file in JOBS_DIR.glob("*.json"):
        try:
            with open(job_file, "r+", encoding="utf-8") as f:
                job_data = json.load(f)

                if str(job_data.get("job_id")) == str(job_id):
                    job_data["status"] = "cancelled"
                    f.seek(0)
                    json.dump(job_data, f, indent=2)
                    f.truncate()
                    updated = True
                    break

        except Exception as e:
            print(f"Error cancelling {job_file}: {e}")

    if updated:
        return render_template(
            "partials/alert.html",
            type="success",
            title="Job Cancelled",
            message=f"Job <b>{project_name}</b> has been cancelled successfully."
        )
    else:
        return render_template(
            "partials/alert.html",
            type="error",
            title="Cancel Failed",
            message=f"Job <b>{project_name}</b> not found or could not be cancelled."
        ), 404

@app.route('/remove-job', methods=['DELETE'])
def remove_job():
    # Ambil data baik dari form, query param, atau JSON (HTMX bisa kirim dari mana saja)
    data = request.get_json(silent=True) or {}
    job_id = (
        request.form.get("job_id")
        or request.args.get("job_id")
        or data.get("job_id")
    )
    project_name = (
        request.form.get("project_name")
        or request.args.get("project_name")
        or data.get("project_name")
        or "Unknown Project"
    )

    if not job_id:
        return render_template(
            "partials/alert.html",
            type="error",
            title="Remove Failed",
            message="Job ID not provided."
        ), 400

    deleted = False
    for job_file in JOBS_DIR.glob("*.json"):
        try:
            with open(job_file, "r", encoding="utf-8") as f:
                job_data = json.load(f)
            if str(job_data.get("job_id")) == str(job_id):
                f.close()
                os.remove(job_file)
                deleted = True
                break
        except Exception as e:
            print(f"Error removing {job_file}: {e}")

    if deleted:
        return render_template(
            "partials/alert.html",
            type="success",
            title="Queue Removed",
            message=f"Job <b>{project_name}</b> was removed from queue."
        )
    else:
        return render_template(
            "partials/alert.html",
            type="error",
            title="Remove Failed",
            message=f"Job <b>{project_name}</b> not found."
        ), 404


@app.route('/partials/close-modal')
def close_modal():
    return "", 200


# ====================================================================
# Background Worker Thread - SEQUENTIAL EXECUTION
# ====================================================================

def find_client_script():
    """Cari lokasi Client.py otomatis"""
    env_path = os.environ.get("PENTEST_CLIENT_PATH")
    if env_path and os.path.isfile(env_path):
        return os.path.abspath(env_path)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base_dir, "Client.py"),
        os.path.join(base_dir, "Pentest", "Client.py"),
        os.path.join(base_dir, "pentest", "Client.py"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return os.path.abspath(path)
    return None

def job_worker():
    """Worker thread yang menjalankan job SATU PER SATU dari queue"""
    global current_running_job
    print("🔄 Job worker started - Sequential execution mode")
    while True:
        try:
            # Ambil job dari queue (blocking, tunggu sampai ada job)
            job_data = job_queue.get(timeout=1)
            job_id = job_data['job_id']
            current_running_job = job_id
            print(f"\n{'='*60}")
            print(f"▶️ Starting job: {job_id}")
            print(f"   Project: {job_data['project_name']}")
            print(f"   Target: {job_data['target_ip']}")
            print(f"   CVE: {job_data['cve_module']}")
            print(f"{'='*60}\n")
            # Update status ke 'running'
            update_job_status(
                job_id,
                'running',
                started_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            )
            # Start subprocess (improved: find client, stream stdout to log & console)
            try:
                client_script = find_client_script()
                if not client_script:
                    raise FileNotFoundError("Client.py not found. Set PENTEST_CLIENT_PATH or put Client.py in ./Pentest")
                python_exec = os.environ.get("PENTEST_PYTHON") or sys.executable or "python3"
                # Build command matching your Client.py's argparse: --ip and --cve
                command = [
                    python_exec, "-u", client_script,
                    "--ip", job_data['target_ip'],
                    "--cve", job_data['cve_module']
                ]
                log_file_path = JOBS_DIR / f"{job_id}.log"
                with open(log_file_path, 'a', encoding='utf-8') as log_file:
                    process = subprocess.Popen(
                        command,
                        cwd=os.path.dirname(client_script),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1
                    )
                    # Simpan process info
                    active_jobs[job_id] = {
                        'process': process,
                        'job_data': job_data,
                        'start_time': time.time(),
                        'log_path': str(log_file_path)
                    }
                    # Stream stdout line-by-line
                    try:
                        for line in process.stdout:
                            if line is None:
                                break
                            log_file.write(line)
                            log_file.flush()
                            print(f"[{job_id}] {line.rstrip()}")
                    except Exception as e:
                        print(f"[{job_id}] Error while streaming output: {e}")
                    # Tunggu sampai process selesai
                    return_code = process.wait()
                # Update status based on return code
                if return_code == 0:
                    print(f"✅ Job {job_id} completed successfully")
                    update_job_status(
                        job_id,
                        'completed',
                        finished_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        progress=100,
                        return_code=return_code
                    )
                else:
                    print(f"❌ Job {job_id} failed with return code {return_code}")
                    update_job_status(
                        job_id,
                        'failed',
                        finished_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        error=f"Process exited with code {return_code}",
                        return_code=return_code
                    )
            except Exception as e:
                print(f"❌ Job {job_id} failed with exception: {e}")
                update_job_status(
                    job_id,
                    'failed',
                    finished_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    error=str(e)
                )
            finally:
                # Cleanup
                if job_id in active_jobs:
                    # close any file handles if present (not strictly needed here)
                    try:
                        lf = active_jobs[job_id].get('log_file')
                        if lf:
                            lf.close()
                    except:
                        pass
                    try:
                        del active_jobs[job_id]
                    except:
                        pass
                current_running_job = None
                job_queue.task_done()
                print(f"🏁 Job {job_id} finished\n")
        except queue.Empty:
            # Tidak ada job di queue, tunggu
            time.sleep(1)
        except Exception as e:
            print(f"❌ Worker error: {e}")
            time.sleep(1)

def progress_monitor():
    """Monitor progress untuk job yang sedang running"""
    while True:
        time.sleep(3)  # Update setiap 3 detik
        if current_running_job and current_running_job in active_jobs:
            job_info = active_jobs[current_running_job]
            elapsed = time.time() - job_info['start_time']
            # Simulasi progress berdasarkan waktu (max 95%)
            progress = min(95, int((elapsed / 180) * 95))  # 180 detik = 3 menit
            job = get_job(current_running_job)
            if job and job.get('progress', 0) != progress:
                update_job_status(current_running_job, 'running', progress=progress)

# Start worker thread
worker_thread = threading.Thread(target=job_worker, daemon=True)
worker_thread.start()

# Start progress monitor thread
progress_thread = threading.Thread(target=progress_monitor, daemon=True)
progress_thread.start()

# Pastikan secret key tetap konsisten dan session bisa tersimpan
app.config['SESSION_COOKIE_DOMAIN'] = False  # biarkan Flask handle domain cookie
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("🛡️ AutoPentest Dashboard")
    print("=" * 60)
    print(f"📁 Jobs directory: {JOBS_DIR.absolute()}")
    print(f"⚙️ Sequential execution: ENABLED")
    print(f"🔄 Background monitoring: ACTIVE")
    print(f"🌐 Server: http://localhost:5000")
    print("=" * 60 + "\n")
    app.run(debug=True, port=5000, host='0.0.0.0', use_reloader=False)