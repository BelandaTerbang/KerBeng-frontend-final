# KerBeng-frontend-final
Kode FrontEnd Autopentest
# AutoPentest Dashboard

AutoPentest adalah platform yang dirancang untuk melakukan **otomatisasi penetration testing** menggunakan modul CVE, job queue, dan dashboard real-time.

Framework ini menggabungkan:

* **Python Flask** untuk backend & dashboard
* **HTMX** untuk real-time UI update
* **TailwindCSS** untuk frontend
* **Client.py** untuk mengeksekusi modul CVE
* Sistem job management lengkap:

  * Queue
  * Sequential execution
  * Progress monitoring
  * Log tracking
  * Auto-refresh status

Project ini sangat cocok untuk:

✔ Pembelajaran Red Team / Pentest
✔ Automasi scan → pilih CVE → exploit
✔ Mengembangkan CVE module custom
✔ Dashboard monitoring pentest

---

# 1. Clone Repository

Gunakan git untuk mengambil project:

```bash
git clone https://github.com/BelandaTerbang/KerBeng-frontend-final.git
cd AutoPentest
```

Jika sudah pernah clone dan ingin update:

```bash
git pull origin main
```

---

# 2. Setup Virtual Environment

Disarankan Python **3.10+**.

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux / MacOS

```bash
python3 -m venv venv
source venv/bin/activate
```

---

# 3. Install Dependencies

Jika project sudah punya `requirements.txt`:

```bash
pip install -r requirements.txt
```

Jika belum ada, install manual:

```
flask
python-dotenv
```

Install:

```bash
pip install flask python-dotenv requests
```

---

# 4. Buat `.env` (HARUS ADA)

Buat file `.env` di root project:

```
ADMIN_USER=isiusername
ADMIN_PASS=isipassword
SECRET_KEY=your-secure-secret-key
```

# 5. Struktur Folder Project

Struktur minimal project:

```
Client.py                      # Pentest executor
AutoPentest/
│
├── app.py                     # Flask backend + job queue + API   
├── CVE/                       # Folder modul-modul CVE
│   ├── CVE12_2122.py
│   ├── CVE22_46169.py
│   └── ...
│
├── jobs/                      # Tempat file job JSON dan log
│   ├── job_xxx.json
│   ├── job_xxx.log
│   └── ...
│
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── scan_vulnerability.html
│   ├── select_cve.html
│   └── partials/
│       ├── jobs_table.html
│       ├── progress_table.html
│       ├── stats_cards.html
│
├── static/                    # JS/CSS jika diperlukan
│
├── venv/                      # Virtual environment
│
└── .env                       # Konfigurasi rahasia
```

---

# 6. Menjalankan Flask Server

Pastikan virtual environment aktif.

```bash
python app.py
```

Server akan berjalan pada:

```
http://127.0.0.1:5000
```

Atau agar bisa diakses LAN:

```
http://0.0.0.0:5000
```

---

# 7. Menjalankan Pentest Secara Manual

Menjalankan Client.py manual:

```bash
python Client.py --ip 192.168.1.10 --cve CVE12_2122
```

Namun dalam mode normal, **dashboard akan menjalankan Client.py secara otomatis** melalui job queue.

---

# 8. Cara Kerja AutoPentest

Flow proses:

1. User input target → klik **Scan Vulnerability**
2. Backend mengirim hasil dummy / real scan
3. User pilih CVE untuk tiap target
4. Backend membuat **job JSON**
5. Job masuk ke **queue**
6. Worker mengeksekusi job satu per satu
7. Log ditulis ke file `.log`
8. Dashboard update status real-time:

   * queued
   * running
   * completed
   * failed
   * cancelled

---

# 9. Troubleshooting

### Flask error: SECRET_KEY missing

Pastikan `.env` ada dan berisi:

```
SECRET_KEY=somethingstrong
```

### Client.py tidak ditemukan

Set path manual:

```
PENTEST_CLIENT_PATH=/full/path/to/Client.py
```

### CVE module tidak ditemukan

Pastikan file ada di folder `/CVE/`.

### Dashboard tidak update otomatis

Pastikan route berikut aktif:

* `/htmx/jobs-table`
* `/htmx/progress-table`
* `/htmx/stats`
