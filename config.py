import os

class Config:
    # Puedes dejar un valor por defecto por si corres local
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")

def get_db_params():
    """
    Lee los parámetros de conexión desde las variables de entorno
    que configuramos en Render: PGHOST, PGUSER, etc.
    """
    return {
        "host": os.environ.get("PGHOST"),
        "database": os.environ.get("PGDATABASE"),
        "user": os.environ.get("PGUSER"),
        "password": os.environ.get("PGPASSWORD"),
        "port": os.environ.get("PGPORT", "5432"),
    }
