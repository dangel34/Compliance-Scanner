from abc import ABC, abstractmethod
import subprocess

class ScannerTarget(ABC):
    def __init__(self):
        self.result = []

    @abstractmethod
    def run_cmd(self,cmd: str) -> str:
        pass

    @abstractmethod
    def check_service(self, name: str) -> str:
        pass
    @abstractmethod
    def check_file_permissions(self, path: str) -> str:
        pass


