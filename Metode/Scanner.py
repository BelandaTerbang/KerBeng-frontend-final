from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any
import subprocess

class Scanner(ABC):
    """
    Scanner interface menentukan metode-metode untuk membuat scanning team
    Abstract Scanner -- abstract product dalam kasus abstract factory
    """
    def __init__(self) -> None:
        self._outputscanparam = []
        self._targetIP = []
        self._targetPort = []
        self._scnParams = []
        self._outputScanFile = None

    @abstractmethod
    def scanTarget(self, params) -> str:
        pass

    @property
    def outScanFile(self):
        return self._outputScanFile
    
    @outScanFile.setter
    def outScanFile(self, osf):
        self._outputScanFile = osf

    @property
    def targetIP(self):
        return self._targetIP
    
    @targetIP.setter
    def targetIP(self, ipAdds):
        self._targetIP = ipAdds

    @property
    def targetPorts(Self):
        return Self._targetPort
    
    @targetPorts.setter
    def targetPorts(self, ports):
        self._targetPort = ports

    @property
    def params(self):
        return self._scnParams
    
    @params.setter
    def params(self, scnParams):
        self._scnParams = scnParams

    @property
    def outScanParam(self):
        return self._outputscanparam
    
    @outScanParam.setter
    def outScanParam(self, fName):
        self._outputscanparam = ["-oN", fName]

class NMAP(Scanner):
    """
    NMAP(Snanner) adalah concrate scanner yang mengimplementasi metode
    pada abstract scanner
    """
    """ def __init__(self) -> None:
        self._targetsIP = []
        self._targetsPorts = []
        self._params = []

    def setTargetIP(self, ipAddrs) -> None:
        self._ipAddresses = ipAddrs

    def setTargetPorts(self, ports) -> None:
        self._ports = ports
    
    def setParams(self, params) -> None:
        self._params = params """

    def scanTarget(self, params) -> str:
        print("scaning network using NMAP")

class Shodan(Scanner):
    """
    Shodan(Snanner) adalah concrate scanner yang mengimplementasi metode
    pada abstract scanner
    """
    def __init__(self) -> None:
        self._ipAddresses = []
        self._ports = []
        self._params = []

    def setTargetIP(self, ipAddrs) -> None:
        self._ipAddresses = ipAddrs

    def setTargetPorts(self, ports) -> None:
        self._ports = ports
    
    def setParams(self, params) -> None:
        self._params = params
        
    def scanTarget(self) -> None:
        print("scaning network using Shodan")