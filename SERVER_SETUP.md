# Server Setup Guide — KerBeng AutoPentest

## 1. System Packages

```bash
sudo apt install python3-venv -y
sudo apt install mysql-client -y
sudo apt install libreoffice -y
sudo apt install libreoffice-writer python3-uno -y
sudo apt install unoconv -y
```

## 2. Virtual Environment

```bash
# Buat venv
python3 -m venv sipentes
source sipentes/bin/activate

# Install dependencies
# ⚠️ Hapus baris 'pywin32-ctypes' dari Requirements.txt dulu (Windows only)
pip install -r Requirements.txt

# Install python-docx (untuk generate dokumen .docx)
pip install python-docx
```

## 3. Fix unoconv di venv (symlink uno)

> Diperlukan agar `unoconv` bisa jalan di dalam venv.

```bash
VENV_SITE="/home/kerjabengkel-ubuntu/kerbeng/KerBeng-frontend-final/sipentes/lib/python3.10/site-packages"

ln -sf /usr/lib/python3/dist-packages/uno.py       "$VENV_SITE/uno.py"
ln -sf /usr/lib/python3/dist-packages/unohelper.py "$VENV_SITE/unohelper.py"
ln -sf /usr/lib/python3/dist-packages/com           "$VENV_SITE/com"
```

## 4. Simpan Sudo Password ke Keyring

> Digunakan oleh `nmap` (butuh sudo).

```bash
python AutoPentest/testKeyring.py
# → masukkan sudo password saat diminta
```

## 5. File yang Harus Ada di Root Project

Salin manual ke folder yang sama dengan `Client.py`:

```
KerBeng-frontend-final/
├── Logo Horizontal.png    ← untuk semua CVE report (header dokumen)
└── ugm.png                ← untuk CVE22_46169 report (cover page)
```

## 6. Buat File `.env`

Buat file `Frontend/.env`:

```env
ADMIN_USER=admin
ADMIN_PASS=password_kamu
SECRET_KEY=random_secret_key_panjang
PENTEST_CLIENT_PATH=/home/kerjabengkel-ubuntu/kerbeng/KerBeng-frontend-final/Client.py
```

## 7. Jalankan Flask

```bash
source sipentes/bin/activate
cd Frontend/
python app.py
```

---

## Setelah Server Restart

Cukup jalankan ulang:

```bash
source ~/kerbeng/KerBeng-frontend-final/sipentes/bin/activate
cd ~/kerbeng/KerBeng-frontend-final/Frontend/
python app.py
```

> Symlink uno dan keyring sudah tersimpan permanen, tidak perlu diulang.

---

## Perubahan Kode (Sudah Diapply)

### `Metode/Report.py`
- Tambah atribut `_outRepName = "Pentesting_Report"` di `__init__`
- Tambah property `outRepName` dengan setter yang otomatis format nama jadi `{name}_Report`
- `generate_report()` sekarang pakai `self._outRepName` untuk nama file (bukan hardcoded `Pentesting_Report`)

```python
# Sebelum
self._document.save(f"{self.outRepFile}Pentesting_Report.docx")
subprocess.run(["unoconv", "-f", "pdf", f"{self.outRepFile}Pentesting_Report.docx"], ...)

# Sesudah
self._document.save(f"{self.outRepFile}{self._outRepName}.docx")
subprocess.run(["unoconv", "-f", "pdf", f"{self.outRepFile}{self._outRepName}.docx"], ...)
```

---

### `CVE/CVE12_2122/CVE12_2122.py`
- Tambah `import os as _os` dan `import re as _re`
- Hitung `_PROJECT_ROOT` (2 level di atas file ini) dan `_REPORT_DIR` ke `Frontend/reports/`
- `exploitingTarget()`: exploit output (`{ip}_exploit.txt`) sekarang disimpan di subfolder `Frontend/reports/{project_name}/`
- `reporting()`: report (`.docx` & `.pdf`) disimpan di subfolder `Frontend/reports/{project_name}/` dengan nama `{project_name}_Report`
- Nama project diambil dari `params['project_name']` dan di-sanitize (hapus karakter spesial, spasi → `_`)

```python
# Sebelum
exp.outExpFile = "CVE/CVE12_2122/"
rep.outRepFile = "CVE/CVE12_2122/"

# Sesudah
project_dir = Frontend/reports/{project_name}/  (path absolut, dibuat otomatis)
exp.outExpFile = project_dir
rep.outRepFile = project_dir
rep.outRepName = safe_name  # → file: {safe_name}_Report.pdf
```

---

### `Client.py`
- Tambah argumen `--project` (opsional, default: `"Pentesting"`) di argparse
- Nilai `--project` dimasukkan ke `params` dict sebagai `project_name`

```python
# Sebelum
params = {"ipAddrs": args.ip}

# Sesudah
params = {"ipAddrs": args.ip, "project_name": args.project}
```

---

### `Frontend/app.py`
- Tambah `"--project", job_data.get('project_name', 'Pentesting')` ke command subprocess `job_worker()`
- Route `/api/reports/<project_name>/download` dan `/view`: sekarang cari PDF di subfolder `reports/{project_name}/` dulu, fallback ke `reports/` jika tidak ada

```python
# Sebelum (command subprocess)
command = [python_exec, "-u", client_script, "--ip", ..., "--cve", ...]

# Sesudah
command = [python_exec, "-u", client_script, "--ip", ..., "--cve", ..., "--project", job_data.get('project_name', 'Pentesting')]
```

```python
# Logika cari PDF di download/view route
subdir_path = reports/{safe_name}/{safe_name}_Report.pdf   # cari di subfolder dulu
flat_path   = reports/{safe_name}_Report.pdf               # fallback (file lama)
```

---

## Struktur Output Report

Setelah pentest selesai, semua file tersimpan otomatis dalam satu subfolder:

```
Frontend/reports/
└── {nama_project}/
    ├── {nama_project}_Report.docx
    ├── {nama_project}_Report.pdf
    └── {ip_target}_exploit.txt
```

Contoh jika project name = `pentest1`, target = `10.33.102.225`:
```
Frontend/reports/
└── pentest1/
    ├── pentest1_Report.docx
    ├── pentest1_Report.pdf
    └── 10.33.102.225_exploit.txt
```
