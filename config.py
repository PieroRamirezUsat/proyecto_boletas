import os

class Config:
    # Clave secreta para Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")


def get_db_params():
    """
    Parámetros para conectarse a la BD de Render usando el host interno.
    Como es host interno, desactivamos SSL (sslmode=disable).
    """
    return {
        "host": os.environ["PGHOST"],
        "database": os.environ["PGDATABASE"],
        "user": os.environ["PGUSER"],
        "password": os.environ["PGPASSWORD"],
        "port": os.environ.get("PGPORT", "5432"),
        "sslmode": "disable",  # <- ESTO ES LO IMPORTANTE
    }
