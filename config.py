import os

class Config:
    # Clave secreta de Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")


def get_db_params():
    """
    Devuelve los parámetros de conexión a PostgreSQL
    usando las variables de entorno definidas en Render.
    """
    return {
        "host": os.environ["PGHOST"],
        "database": os.environ["PGDATABASE"],
        "user": os.environ["PGUSER"],
        "password": os.environ["PGPASSWORD"],
        "port": os.environ.get("PGPORT", "5432"),
    }
