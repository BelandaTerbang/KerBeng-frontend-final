from Metode import *
import keyring


class NmapScanner(Scanner):

    def __init__(self) -> None:
        super().__init__()
        self._scanParams = {
            "scnParams":["sudo", "-S","nmap", "-sV", "-sC", "-Pn", "-O"],
            "oputFile":"CVE/CVE12_2122/nmap_results.txt"
        }
    
    def scanTarget(self, prm):
        self.targetIP = [prm]
        self.outScanParam = self._scanParams['oputFile']
        self.outScanFile = self._scanParams['oputFile']
        self.params = self._scanParams['scnParams']
        #print(f"target IP: {self.targetIP}")
        nmap_command = self.params
        nmap_command.extend(self.targetIP)
        nmap_command.extend(self.outScanParam)
        #print(f"nmap_command is: {nmap_command}")
        result_data = {
            'success' : False,
            'output' : '',
            'error' : '',
            'message' : ''
        }
        sudo_pass = keyring.get_password("system", "sudo")
        try:
            result = subprocess.run(nmap_command,
                                    input=sudo_pass,
                                    capture_output=True,
                                    text=True,
                                    check=True)
            result_data['success'] = True
            result_data['output'] = result.stdout
            result_data['message'] = "Scan complated successfully."
        except FileNotFoundError as ef:
            result_data['error'] = str(ef)
            result_data['message'] = f"Nmap not found {ef}.\nPlease make sure Nmap is installed and in your system's PATH."
        except subprocess.CalledProcessError as cpe:
            result_data['error'] = cpe.stderr
            result_data['message'] = f"CalledProcessError: Command failed with return code {cpe.returncode}"
        except Exception as e:
            result_data['error'] = str(e)
            result_data['message'] = "CVE12_2122's IoC: MySQL is not detected"
            print(f"{e}.eor\n")
        return result_data
    