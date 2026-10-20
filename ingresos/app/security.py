import os
from datetime import datetime, timedelta, timezone

import jwt
from dotenv import load_dotenv
from pwdlib import PasswordHash

load_dotenv()

password_hasher = PasswordHash.recommended()


def hash_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("La contraseña debe tener al menos 8 caracteres.")
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return password_hasher.verify(password, password_hash)


def jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET")
    if not secret:
        raise RuntimeError("JWT_SECRET no está configurado en el ambiente.")
    return secret


def create_access_token(company_user_id: int, company_id: int) -> str:
    return jwt.encode(
        {
            "companyUserId": company_user_id,
            "companyId": company_id,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
        },
        jwt_secret(),
        algorithm="HS256",
    )


def decode_access_token(token: str) -> tuple[int, int]:
    payload = jwt.decode(
        token,
        jwt_secret(),
        algorithms=["HS256"],
        options={"require": ["companyUserId", "companyId", "exp"]},
    )
    member_id = payload["companyUserId"]
    company_id = payload["companyId"]
    if (type(member_id) is not int or member_id <= 0
            or type(company_id) is not int or company_id <= 0):
        raise ValueError("El token no es válido.")
    return member_id, company_id
