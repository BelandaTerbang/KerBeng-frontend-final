from AutoPentest import APentest
from Metode import *
from .Banner_46169 import CBanner
from .Enum_46169 import CEnum
from .VulnAnls_46169 import CVulnAnalist
from .Scanner_46169 import NmapScanner
from .Exploit_46169 import CExploit
from .Report_46169 import CReport
from utils import PentestUtils as pu

class CVE22_46169Cacti1(APentest):
    """
    CVE22_46169Cacti adalah concrate class yang mewarisi abstract class
    AutoPentest berisi implementasi unik dari langkah-langkah automation
    pentesting
    """
    def __init__(self) -> None:
        super().__init__()

    def banner(self) -> None:
        ban = CBanner()
        ban.setBanner()
        del ban
        #choice = ban.makeChoice()
        #print(f"Your choice is {choice}")

    def scanning(self, params) -> Scanner:
        print(f"CVE22_46169Cacti says I'm scanning target {self.getTargets} from {self.getLHost}")
        for ip in self.getTargets:
            if pu.isPrivateIP(ip) == True:
                pindai = NmapScanner()
            else: pindai = Shodan()
            pindai.scanTarget(ip)
            self.scnOutFile = pindai.outScanFile
        del pindai

    def enumerating(self, params) -> Enumerator:
        print("CVE22_46169Cacti says I'm enumerating network target")
        enum = CEnum()
        enum.outEnumFile = "enum_results.txt"
        enum.sourceFile = self.scnOutFile
        enum.enumTarget()
        self.enumOutFile = enum.outEnumFile
        del enum

    def vulnerAnalysist(self, params) -> VulnerAnalist:
        print("CVE22_46169Cacti says I'm analysing vulnerability network target")
        vulnAnls = CVulnAnalist()
        vulnAnls.targets = self.enumOutFile
        vulnAnls.bufHub = self.bufHub
        vulnAnls.startAnalising()
        self.setItem("vulnList", vulnAnls.listVulners)
        """ for index, item in enumerate(vulnAnls.listVulners):
            print(f"index: {index}, value: {item}")
        print(self.bufHub) """
        del vulnAnls

    def exploitingTarget(self, params) -> Exploit:
        print("CVE22_46169Cacti says I'm exploiting network target")
        exp = CExploit()
        exp.lHost = self.getLHost
        exp.makePayload(self.getItem("vulnList"))
        exp.startExploit()
        del exp
    
    def reporting(self, params):
        rep = CReport()
        rep.generate_report()
        del rep
