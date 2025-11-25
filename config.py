import os

class Config:
    # Si Railway NO envía SECRET_KEY, usa esta en local
    SECRET_KEY = os.environ.get("SECRET_KEY", "super_clave_secreta_local")

def get_db_params():
    return {
        "host": os.environ.get("DB_HOST", "localhost"),
        "database": os.environ.get("DB_NAME", "bd_gobierno"),
        "user": os.environ.get("DB_USER", "postgres"),
        "password": os.environ.get("DB_PASSWORD", "hola1"),
        "port": int(os.environ.get("DB_PORT", 5432)),
    }
