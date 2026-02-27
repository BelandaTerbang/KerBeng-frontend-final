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
├── Logo Horizontal.png    ← untuk semua CVE report
└── ugm.png                ← untuk CVE22_46169 report
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

| File | Perubahan |
|---|---|
| `Metode/Report.py` | Tambah `outRepName` property — nama file output kini dinamis |
| `CVE/CVE12_2122/CVE12_2122.py` | Output report & exploit diarahkan ke `Frontend/reports/{project_name}/` |
| `Client.py` | Tambah argumen `--project` untuk menerima nama project dari frontend |
| `Frontend/app.py` | Tambah `--project` ke subprocess; route download/view cari PDF di subfolder |

## Struktur Output Report

Setelah pentest selesai, file tersimpan otomatis di:

```
Frontend/reports/
└── {nama_project}/
    ├── {nama_project}_Report.docx
    ├── {nama_project}_Report.pdf
    └── {ip_target}_exploit.txt
```

Contoh jika project name = `pentest1`:
```
Frontend/reports/
└── pentest1/
    ├── pentest1_Report.docx
    ├── pentest1_Report.pdf
    └── 10.33.102.225_exploit.txt
```
