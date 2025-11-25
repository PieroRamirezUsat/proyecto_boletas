import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")


def get_db_params():
    return {
        "host": os.environ["PGHOST"],
        "dbname": os.environ["PGDATABASE"],  # 👈 OJO AQUÍ
        "user": os.environ["PGUSER"],
        "password": os.environ["PGPASSWORD"],
        "port": os.environ.get("PGPORT", "5432"),
        "sslmode": "require"
    }

