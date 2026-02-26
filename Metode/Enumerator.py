from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any

class Enumerator(ABC):
    """
    Enumerator interface menentukan metode-metode untuk melakukan enumerasi
    Abstract Enumerator -- abstract product dalam kasus abstract factory
    """
    def __init__(self):
        self._sourceFile = None
        self._outEnumFile = None
        self._dataEnum = []

    @property
    def dataEnum(self):
        return self._dataEnum
    
    @dataEnum.setter
    def dataEnum(self, oef):
        self._dataEnum = oef
        
    @property
    def outEnumFile(self):
        return self._outEnumFile
    
    @outEnumFile.setter
    def outEnumFile(self, oef):
        self._outEnumFile = oef
        
    @property
    def sourceFile(self):
        return self._sourceFile
    
    @sourceFile.setter
    def sourceFile(self, sf):
        self._sourceFile = sf

    @abstractmethod
    def enumTarget(self) -> None:
        pass

    @abstractmethod
    def setTarget(self, IPAddrs) -> None:
        pass

    @abstractmethod
    def setTool(self, tool, params) -> None:
        pass

class MetasEnum(Enumerator):
    """ 
    MetasEnum adalah concrate enumerator dengan menggunakan metasplooit tools
    """

    def __init__(self) -> None:
        self._ipAddresses = []
        self._tool = "msf"
        self._params = []

    def setTarget(self, IPAddrs) -> None:
        self._ipAddresses = IPAddrs

    def setTool(self, tool, params) -> None:
        self._tool = tool
        self._params = params

    def enumTarget(self) -> None:
        print("Enumerating target using Metasploit modul")