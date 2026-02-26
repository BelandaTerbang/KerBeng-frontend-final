from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any
import subprocess

class VulnerAnalist(ABC):
    """
    VulnerAnalist interface merupakan abstract class yang bertugas melakukan
    analisis kerentanan target
    Abstract Vulnerability Analist -- abstract product dalam kasus abstract factory
    """
    def __init__(self):
        self._command = None
        self._isVulner = False
        self._targets = None
        self._listVulners = []
        self._outAnalFile = None
    
    @property
    def listVulners(self):
        return self._listVulners
    
    @listVulners.setter
    def listVulners(self, list_baru):
        if all(isinstance(item, list) for item in list_baru):
            self._listVulners = list_baru
        else:
            raise ValueError("Seluruh items harus berupa lists.")

    def addToList(self, item_baru):
        if isinstance(item_baru, list):
            self._listVulners.append(item_baru)
        else:
            raise ValueError("items harus berupa lists")
        
    @property
    def targets(self):
        return self._targets
    
    @targets.setter
    def targets(self, trgt):
        self._targets = trgt

    @property
    def isVulner(self):
        return self._isVulner
    
    @isVulner.setter
    def isVulner(self, vuln):
        self._isVulner = vuln
        
    @property
    def textCommand(self):
        return self._command
    
    @textCommand.setter
    def textCommand(self, cmd):
        self._command = cmd
    
    @property
    def outAnalFile(self):
        return self._outAnalFile
    
    @outAnalFile.setter
    def outAnalFile(self, oef):
        self._outAnalFile = oef

    @abstractmethod
    def startAnalising(self) -> None:
        pass

class msfVulnerAnalist(VulnerAnalist):
    """
    msf vulnerability analist adalah concrate class dari vulnerability analist
    yang bertugas melakukan analisis kerentanan menggunakan toll metasploit
    """

    def __init__(self) -> None:
        self._setTarget = []
        self._setParams = []
  
    def startAnalising(self) -> None:
        print("Vulnerability analising using msf modul")