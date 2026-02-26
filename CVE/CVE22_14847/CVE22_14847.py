from AutoPentest import APentest
from Metode import *

class CVE22_14847Mikrotik1(APentest):
    
    def banner(self) -> None:
        ban = super().banner()
        print("Mikrotik banner is printing")
        return ban

    def scanning(self, params) -> Scanner:
        print("CVE22_14847Mikrotik says I'm scanning target network")
        if params['scan'] == "nmap":
            pindai = NMAP()
            pindai.scanTarget()
        elif params['scan'] == "shodan":
            pindai = Shodan()
            pindai.scanTarget()
        return pindai
        
    def enumerating(self, params) -> Enumerator:
        print("CVE22_14847Mikrotik says I'm enumerating target network")
        me = MetasEnum()
        me.enumTarget()
        return me

    def vulnerAnalysist(self, params) -> VulnerAnalist:
        print("CVE22_14847Mikrotik says I'm analysing vulnerability target network")
        mfa = msfVulnerAnalist()
        mfa.startAnalising()
        return mfa
    
    def exploitingTarget(self, params) -> Exploit:
        print("CVE22_14847Mikrotik says I'm exploiting target network")

    def reporting(self, params) -> None:
        print("CVE22_14847Mikrotik says I'm generating self report")

__all__ = [CVE22_14847Mikrotik1]