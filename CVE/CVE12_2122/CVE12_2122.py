# Pentest/CVE/CVE12_2122/CVE12_2122.py (Perbaikan Final)

from AutoPentest import APentest
from Metode import *
from .Banner_2122 import CBanner
from .Enum_2122 import CEnum
from .VulnAnls_2122 import CVulnAnalist
from .Scanner_2122 import NmapScanner
from .Exploit_2122 import CExploit
from .Report_2122 import CReport
from utils import PentestUtils as pu

class CVE12_2122(APentest):
    """
    CVE12_2122 adalah concrate class yang mewarisi abstract class
    AutoPentest berisi implementasi unik dari langkah-langkah automation
    pentesting 
    """
    def __init__(self) -> None:
        super().__init__()

    def banner(self) -> None:
        # FUNGSI INI SEKARANG HANYA MENAMPILKAN BANNER.
        # Tidak ada lagi makeChoice() atau input().
        ban = CBanner()
        ban.setBanner()
        del ban

    def infoGathering(self, params):
        # FUNGSI INI SEKARANG LANGSUNG MEMANGGIL FUNGSI INDUKNYA
        # DENGAN PARAMS YANG BENAR DARI WEB.
        # Ini akan mengisi self._targets dengan IP dari web form.
        return super().infoGathering(params)

    def scanning(self, params) -> Scanner:
        print(f"Auto Pentester says I'm scanning target {self.getTargets} from {self.getLHost}")
        for ip in self.getTargets:
            if pu.isPrivateIP(ip) == True:
                pindai = NmapScanner()
            else: pindai = Shodan()
            scan_result = pindai.scanTarget(ip)
            self.scnOutFile = pindai.outScanFile
        del pindai

    def enumerating(self, params) -> Enumerator:
        print("Auto Pentester says I'm enumerating network target")
        enum = CEnum()
        enum.outEnumFile = "CVE/CVE12_2122/enum_results.txt"
        enum.sourceFile = self.scnOutFile
        enum.enumTarget()
        self.enumOutFile = enum.outEnumFile
        self.bufHub = enum.dataEnum
        del enum

    def vulnerAnalysist(self, params) -> VulnerAnalist:
        print("Auto Pentester says I'm analysing vulnerability network target")
        vulnAnls = CVulnAnalist()
        vulnAnls.targets = self.enumOutFile
        vulnAnls.bufHub = self.bufHub
        vulnAnls.outAnalFile = "CVE/CVE12_2122/analyst_results.txt"
        vulnAnls.startAnalising()
        self.setItem("vulnList", vulnAnls.listVulners)
        del vulnAnls

    def exploitingTarget(self, params) -> Exploit:
        print("Auto Pentester says I'm exploiting network target")
        exp = CExploit()
        exp.outExpFile = "CVE/CVE12_2122/"
        exp.makePayload(self.getItem("vulnList"))
        exp.startExploit()
        del exp
    
    def reporting(self, params):
        rep = CReport()
        rep.outRepFile = "CVE/CVE12_2122/"
        print(f"data :\n {self.bufHub}")
        rep.dataReport = self.bufHub
        rep.generate_report()
        del rep