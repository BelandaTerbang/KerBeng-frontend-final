from Metode import *
import re

class CVulnAnalist(VulnerAnalist):

    def __init__(self):
        super().__init__()
        # Daftar versi MySQL dan MariaDB yang rentan berdasarkan CVE-2012-2122
        self._vulnerable_mysql_versions = {
            "5.1": (None, "5.1.63"),
            "5.5": (None, "5.5.24"),
            "5.6": (None, "5.6.6"),
        }

        self._vulnerable_mariadb_versions = {
            "5.1": (None, "5.1.62"),
            "5.2": (None, "5.2.12"),
            "5.3": (None, "5.3.6"),
            "5.5": (None, "5.5.23"),
        }

    def startAnalising(self):
        with open(self.targets, "r") as file:
            lines = file.readlines()
            for line in lines:
                data = line.strip().split()
                if len(data) >= 2:
                    ip = data[0]
                    port = data[1]
                    service = data[2]
                    version = f"{data[2]} {data[3]}"
                    print(f"Processing Check Vulnerability: {ip} {port} {version}")
                    self.isVulner = False
                    if self.is_version_vulnerable(ip, version, service):
                        vulnList = [ip, port]
                        self.addToList(vulnList)
                        print(f"Target {self.listVulners} is seem to be vulnerable :)")

        with open(self.outAnalFile, "w") as outFile:
            for line in lines:
                data = line.strip().split()
                if len(data) >= 2:
                    ip = data[0]
                    try:
                        with open(f"CVE/CVE12_2122/{ip}_vuln.txt", "r") as vulnFile:
                            outFile.write(f"\n\n=========== Vulnerability scanning result of target {ip} \n\n")
                            outFile.write(vulnFile.read())
                    except FileNotFoundError:
                        print(f"No vulnerability file found for {ip}")

    def parse_version(self, version_str):
        return tuple(map(int, re.findall(r'\d+', version_str)))

    def is_version_vulnerable(self, ip, version_str, service):
        version_match = re.search(r'(\d+\.\d+(\.\d+)?)', version_str)
        if not version_match:
            return self.isVulner 

        version_num = version_match.group(1)
        version_tuple = self.parse_version(version_num)
        major_minor = f"{version_tuple[0]}.{version_tuple[1]}"

        if "mysql" in service.lower():
            vuln_versions = self._vulnerable_mysql_versions
        elif "mariadb" in service.lower():
            vuln_versions = self._vulnerable_mariadb_versions
        else:
            return self.isVulner   # not MySQL or MariaDB

        if major_minor in vuln_versions:
            _, upper_bound = vuln_versions[major_minor]
            if self.parse_version(version_num) < self.parse_version(upper_bound):
                self.isVulner = True
                output = f"{service} on {version_str} seems to be vulnerable"
                with open(f"CVE/CVE12_2122/{ip}_vuln.txt", "w") as f:
                    f.write(output)

        return self.isVulner 
