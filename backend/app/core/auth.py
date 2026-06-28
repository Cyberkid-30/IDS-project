from datetime import timedelta, datetime, timezone
from typing import Optional

import jwt as pyjwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from app.core.config import settings


password_hash = PasswordHash([Argon2Hasher()])


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return pyjwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = pyjwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        return payload
    except pyjwt.PyJWTError:
        return None
