import pyfiglet
from Metode import *

class CBanner(Banner):

    def __init__(self) -> None:
        self._textBanner = "Cacti Exploit"

    def setBanner(self) -> None:
        textBanner = pyfiglet.figlet_format(self._textBanner)
        print(textBanner)
        print("Chose the execution mode: ")
        print("1. Local")
        print("2. PUblic")
    
    def makeChoice(self) -> list:
        choice = input("Enter your choice (1 or 2): ")
        return choice