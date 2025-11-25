# validacion.py
import re
from datetime import datetime

# DNI: exactamente 8 dígitos numéricos
dni_regex = re.compile(r'^\d{8}$')

# Nombres / Apellidos: solo letras (con tildes), Ñ/ñ y espacios
nombre_regex = re.compile(r'^[A-Za-zÁÉÍÓÚÜÑáéíóúüñ ]+$')

# Correo simple: algo@algo.dominio
correo_regex = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

# Caja / legajo / carpeta: letras, números, espacios, - y /
caja_regex = re.compile(r'^[0-9A-Za-zÁÉÍÓÚÜÑáéíóúüñ \-\/]*$')


def validar_dni(valor: str) -> bool:
    """DNI obligatorio, 8 dígitos numéricos."""
    if not valor:
        return False
    return bool(dni_regex.match(valor.strip()))


def validar_nombre(valor: str) -> bool:
    """Sirve tanto para nombres como apellidos (solo letras y espacios)."""
    if not valor:
        return False
    return bool(nombre_regex.match(valor.strip()))


def validar_correo(valor: str) -> bool:
    """
    El correo es opcional:
    - Si viene vacío -> es válido
    - Si viene con algo -> debe cumplir formato correo
    """
    if not valor:
        return True
    return bool(correo_regex.match(valor.strip()))


def validar_anio(valor: str) -> bool:
    """Año entre 1980 y el año actual."""
    try:
        anio = int(valor)
    except (TypeError, ValueError):
        return False
    return 1980 <= anio <= datetime.now().year


def validar_mes(valor: str) -> bool:
    """Mes entre 1 y 12."""
    try:
        mes = int(valor)
    except (TypeError, ValueError):
        return False
    return 1 <= mes <= 12


def validar_caja_legajo_carpeta(valor: str) -> bool:
    """
    Permite vacío, pero si hay texto:
    solo letras, números, espacios, guion (-) y slash (/).
    """
    if not valor:
        return True
    return bool(caja_regex.match(valor.strip()))
