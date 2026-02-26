from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any
from docx import Document
from docx.shared import Pt, Cm, Inches
from docx.enum.text import WD_PARAGRAPH_ALIGNMENT
from datetime import date
import subprocess

class Report(ABC):

    def __init__(self):
        super().__init__()
        self._document = Document()
        self._outRepFile = None
        self._dataReport = []
        self._data = {}

    def generate_report(self):
        self.initData()
        self.add_header()
        self.creat_cover_page()
        self.add_introduction()
        self.add_scope()
        self.add_methodelogy()
        self.add_vulnerability_ident()
        self.add_vulnerability_scanning()
        self.add_vulnerability_exploit()
        self.add_recommendation()
        self._document.save(f"{self.outRepFile}Pentesting_Report.docx")
        subprocess.run(["unoconv", "-f", "pdf", f"{self.outRepFile}Pentesting_Report.docx"], stderr=subprocess.DEVNULL)
        print("Pentesting report generated successfully")

    @property
    def dataReport(self):
        return self._dataReport
    
    @dataReport.setter
    def dataReport(self, oef):
        self._dataReport = oef
        
    @property
    def outRepFile(self):
        return self._outRepFile
    
    @outRepFile.setter
    def outRepFile(self, oef):
        self._outRepFile = oef

    @abstractmethod
    def initData(self):
        pass

    @abstractmethod
    def add_header(self):
        pass

    @abstractmethod
    def creat_cover_page(self):
        pass

    @abstractmethod
    def add_introduction(self):
        pass

    @abstractmethod
    def add_scope(self):
        pass

    @abstractmethod
    def add_methodelogy(self):
        pass

    @abstractmethod
    def add_vulnerability_ident(self):
        pass

    @abstractmethod
    def add_vulnerability_scanning(self):
        pass

    @abstractmethod
    def add_vulnerability_exploit(self):
        pass

    @abstractmethod
    def add_recommendation(self):
        pass



