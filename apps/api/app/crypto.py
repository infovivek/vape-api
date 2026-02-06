import base64
from cryptography.fernet import Fernet

from .settings import settings


def _get_fernet() -> Fernet:
    if not settings.encryption_key:
        raise RuntimeError("VAPT_ENCRYPTION_KEY must be set")
    return Fernet(settings.encryption_key.encode())


def encrypt_value(value: str) -> str:
    fernet = _get_fernet()
    return fernet.encrypt(value.encode()).decode()


def decrypt_value(value: str) -> str:
    fernet = _get_fernet()
    return fernet.decrypt(value.encode()).decode()
