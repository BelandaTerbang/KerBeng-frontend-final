# Pentest/Client.py (Versi yang Benar)

import argparse
from AutoPentest import APentest
from CVE import *

def client_code(autoPentest: APentest, params) -> None:
    autoPentest.startPentest(params)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoPentest Framework Runner")
    parser.add_argument("--ip", required=True, help="Target IP Address or range.")
    parser.add_argument("--cve", required=True, help="CVE module to run (e.g., CVE12_2122).")
    
    args = parser.parse_args()

    params = {
        "ipAddrs": args.ip
    }

    pentest_module = None
    if args.cve == "CVE12_2122":
        pentest_module = CVE12_2122.CVE12_2122()
    elif args.cve == "CVE22_46169":
        pentest_module = CVE22_46169.CVE22_46169Cacti1()

    if pentest_module:
        client_code(pentest_module, params)
    else:
        print(f"Error: CVE module '{args.cve}' not found.")