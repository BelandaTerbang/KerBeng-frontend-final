import pyfiglet
from Metode import *
from utils import PentestUtils as pu

class CBanner(Banner):

    def __init__(self) -> None:
        super().__init__()
        self._textBanner = "MySQL Exploit"

    def setBanner(self) -> None:
        textBanner = pyfiglet.figlet_format(self._textBanner)
        print(textBanner)
    
    def makeChoice(self) -> list:
        choice = input("Set the target IP Address: ")
        return choice 