from Metode import *


class NmapScanner(Scanner):

    def __init__(self) -> None:
        super().__init__()
        self._scanParams = {
            #"scnParams":["nmap", "-sV", "-sC", "-Pn", "--script", "http-title", "http-enum"],
            "scnParams":["nmap", "-sV", "-Pn", "--script", "http-enum"],
            "oputFile":"nmap_results.txt"
        }

    def scanTarget(self, prm) -> str:
        self.targetIP = [prm]
        self.outScanParam = self._scanParams['oputFile']
        self.outScanFile = self._scanParams['oputFile']
        self.params = self._scanParams['scnParams']
        print(f"target IP: {self.targetIP}")
        nmap_command = self.params
        nmap_command.extend(self.targetIP)
        nmap_command.extend(self.outScanParam)
        #print(f"nmap_command is: {nmap_command}")
        try:
            result = subprocess.run(nmap_command, capture_output=True, text=True, check=True)
            return result
        except FileNotFoundError as ef:
            print(f"Nmap not found {ef}.\nPlease make sure Nmap is installed and in your system's PATH.")
        except subprocess.CalledProcessError as cpe:
            print(f"CalledProcessError: Command failed with return code {cpe.returncode}")
        except Exception as e:
            eor = "CVE22_46169's IoC: Cacti is not detected"
            print(f"{e}.eor\n")
        return eor
    
class ShodanScanner(Scanner):

    def __init__(self) -> None:
        super().__init__()

    def scanTarget(self, params) -> str:
        return super().scanTarget(params)