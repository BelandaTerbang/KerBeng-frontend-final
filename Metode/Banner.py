from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any

class Banner(ABC):
    """
    Banner interface menentukan metode-metode untuk menampilkan banner
    Abstract Enumerator -- abstract product dalam kasus abstract factory
    """

    @abstractmethod
    def setBanner(self) -> None:
        pass

    @abstractmethod
    def makeChoice(self) -> list:
        pass

