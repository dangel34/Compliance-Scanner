from abc import ABC, abstractmethod


class ScannerTarget(ABC):
    @abstractmethod
    def check_service(self, name: str) -> str:
        pass

    @abstractmethod
    def check_file_permissions(self, path: str) -> str:
        pass
