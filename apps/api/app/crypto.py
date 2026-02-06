import base64
from cryptography.fernet import Fernet

from .settings import settings


def _get_fernet() -> Fernet:
    if not settings.encryption_key:
        key = Fernet.generate_key()
        settings.encryption_key = base64.urlsafe_b64encode(base64.urlsafe_b64decode(key)).decode()
    return Fernet(settings.encryption_key.encode())


def encrypt_value(value: str) -> str:
    fernet = _get_fernet()
    return fernet.encrypt(value.encode()).decode()


def decrypt_value(value: str) -> str:
    fernet = _get_fernet()
    return fernet.decrypt(value.encode()).decode()
