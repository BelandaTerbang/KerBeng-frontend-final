from Metode import *
import re

class CVulnAnalist(VulnerAnalist):

    def __init__(self):
        super().__init__()

    def startAnalising(self):
        with open(self.targets, "r") as file:
            lines = file.readlines()
            for line in lines:
                data = line.strip().split()
                if len(data) >= 2:
                    ip = data[0]
                    port = data[1]
                    print(f"Processing Check Vulnerability: {ip}")
                    self.isVulner = False
                    if self.detectVulnerability(ip, port):
                        vulnList = [ip, port]
                        self.addToList(vulnList)
                        print(f"Target {ip} is seem to be vulnerable :)")

        with open("vulnScanReport.txt", "w") as outFile:
            for line in lines:
                data = line.strip().split()
                if len(data) >= 2:
                    ip = data[0]
                    try:
                        with open(f"{ip}_vuln.txt", "r") as vulnFile:
                            outFile.write(f"\n\n=========== Vulnerability scanning result of target {ip} \n\n")
                            outFile.write(vulnFile.read())
                    except FileNotFoundError:
                        print(f"No vulnerability file found for {ip}")
                    

    def detectVulnerability(self, ip, port):
        msf_command = f"msfconsole -qx 'use exploit/linux/http/cacti_unauthenticated_cmd_injection; set RHOSTS {ip}; set RPORT {port}; set TARGETURI /cacti; check; exit'"
        try:
            vuln_result = subprocess.check_output(msf_command, shell=True, stderr=subprocess.STDOUT).decode()
        except subprocess.CalledProcessError as e:
            print("Error occurred during vulnerability detection:")
            print(str(e))
            vuln_result = ""

        if "The target appears to be vulnerable. The target is Cacti version 1.2.22" in vuln_result:
            self.isVulner = True
        elif "The target is not exploitable. Target is not a Cacti application." in vuln_result:
            self.isVulner = True

        if vuln_result:
            vulnerability_output = re.sub(r"\x1b\[[0-9;]*[mK]", "", vuln_result)
            print(f"VulnOut {vulnerability_output}")
            with open(f"{ip}_vuln.txt", "w") as f:
                f.write(vulnerability_output)
        
        return self._isVulner

