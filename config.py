import os

class Config:
    # Si no existe SECRET_KEY en el entorno, usa una por defecto
    SECRET_KEY = os.getenv("SECRET_KEY", "clave_super_secreta_local")

    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_NAME = os.getenv("DB_NAME", "bd_gobierno")
    DB_USER = os.getenv("DB_USER", "postgres")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "hola1")
    DB_PORT = int(os.getenv("DB_PORT", "5432"))


def get_db_params():
    return {
        "host": Config.DB_HOST,
        "database": Config.DB_NAME,
        "user": Config.DB_USER,
        "password": Config.DB_PASSWORD,
        "port": Config.DB_PORT,
    }
