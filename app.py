from werkzeug.security import check_password_hash, generate_password_hash
from config import get_db_params, Config

from validacion import (
    validar_dni,
    validar_nombre,
    validar_correo,
    validar_anio,
    validar_mes,
    validar_caja_legajo_carpeta,
)

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file,
)


import os
import psycopg2
import psycopg2.extras
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from config import get_db_params, Config


app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

# =========================================================
# Config para subida de archivos
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "zip"}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# =========================================================
# Conexión a PostgreSQL
# =========================================================

def get_db():
    params = get_db_params()
    return psycopg2.connect(**params)


# =========================================================
# Login
# =========================================================

@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    mensaje_error = None

    if request.method == "POST":
        dni = (request.form.get("dni") or "").strip()
        password = (request.form.get("password") or "").strip()

        if not dni or not password:
            mensaje_error = "Debes ingresar DNI y contraseña."
            return render_template("login.html", mensaje_error=mensaje_error)

        # NUEVO: validar que el DNI tenga 8 dígitos numéricos
        if not validar_dni(dni):
            mensaje_error = "DNI o contraseña incorrectos."
            return render_template("login.html", mensaje_error=mensaje_error)

        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cur.execute(
            """
            SELECT id_usuario, dni, nombres, apellidos,
                   clave_hash, rol, estado
            FROM usuarios
            WHERE dni = %s
            """,
            (dni,),
        )
        user = cur.fetchone()
        conn.close()

        if not user:
            mensaje_error = "DNI o contraseña incorrectos."
            return render_template("login.html", mensaje_error=mensaje_error)

        if user["estado"] != "A":
            mensaje_error = "Tu cuenta está deshabilitada."
            return render_template("login.html", mensaje_error=mensaje_error)

        hash_db = user["clave_hash"] or ""
        login_ok = False

        # 1) Intentar validar como hash
        try:
            if check_password_hash(hash_db, password):
                login_ok = True
        except Exception:
            # Si clave_hash no es un hash válido, ignoramos el error
            pass

        # 2) Compatibilidad: si en BD está en texto plano (caso antiguo)
        if not login_ok and hash_db == password:
            login_ok = True

        if not login_ok:
            mensaje_error = "DNI o contraseña incorrectos."
            return render_template("login.html", mensaje_error=mensaje_error)

        # Login correcto
        session["usuario_id"] = user["id_usuario"]
        session["dni"] = user["dni"]
        session["nombres"] = user["nombres"]
        session["apellidos"] = user["apellidos"]
        session["rol"] = user["rol"]

        return redirect(url_for("dashboard"))

    return render_template("login.html", mensaje_error=mensaje_error)


# =========================================================
# Registro de usuario (DIGITADOR / CONSULTA)
# =========================================================

@app.route("/registro", methods=["GET", "POST"])
def registro_usuario():
    mensaje_error = None
    mensaje_ok = None

    if request.method == "POST":
        dni = (request.form.get("dni") or "").strip()
        rol = (request.form.get("rol") or "").strip().upper()
        nombres = (request.form.get("nombres") or "").strip()
        apellidos = (request.form.get("apellidos") or "").strip()
        correo = (request.form.get("correo") or "").strip() or None
        password = (request.form.get("password") or "").strip()
        password2 = (request.form.get("password2") or "").strip()

        # Validaciones básicas
        if not dni or not nombres or not apellidos or not password:
            mensaje_error = "DNI, nombres, apellidos y contraseña son obligatorios."
            return render_template("registro_usuario.html",
                                   mensaje_error=mensaje_error)

        if password != password2:
            mensaje_error = "Las contraseñas no coinciden."
            return render_template("registro_usuario.html",
                                   mensaje_error=mensaje_error)

        if rol not in ("DIGITADOR", "CONSULTA"):
            mensaje_error = "Solo se permiten los roles DIGITADOR o CONSULTA."
            return render_template("registro_usuario.html",
                                   mensaje_error=mensaje_error)
        
        # NUEVO: validaciones de formato
        if not validar_dni(dni):
            mensaje_error = "El DNI debe tener exactamente 8 dígitos numéricos."
            return render_template("registro_usuario.html",
                                mensaje_error=mensaje_error)

        if not validar_nombre(nombres):
            mensaje_error = "Los nombres solo deben contener letras y espacios."
            return render_template("registro_usuario.html",
                                mensaje_error=mensaje_error)

        if not validar_nombre(apellidos):
            mensaje_error = "Los apellidos solo deben contener letras y espacios."
            return render_template("registro_usuario.html",
                                mensaje_error=mensaje_error)

        if not validar_correo(correo or ""):
            mensaje_error = "El correo electrónico no tiene un formato válido."
            return render_template("registro_usuario.html",
                                mensaje_error=mensaje_error)


        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Verificar si ya existe usuario con ese DNI
        cur.execute("SELECT 1 FROM usuarios WHERE dni = %s", (dni,))
        if cur.fetchone():
            conn.close()
            mensaje_error = "Este DNI ya se encuentra registrado."
            return render_template("registro_usuario.html",
                                   mensaje_error=mensaje_error)

        # Guardar usuario con contraseña hasheada
        hash_pass = generate_password_hash(password)

        cur.execute(
            """
            INSERT INTO usuarios (dni, nombres, apellidos, correo,
                                  clave_hash, rol, estado)
            VALUES (%s,%s,%s,%s,%s,%s,'A')
            """,
            (dni, nombres, apellidos, correo, hash_pass, rol),
        )

        # Si el rol es DIGITADOR, creamos también el trabajador (si no existe)
        if rol == "DIGITADOR":
            cur.execute(
                "SELECT id_trabajador FROM trabajadores WHERE dni = %s",
                (dni,),
            )
            trab = cur.fetchone()
            if not trab:
                cur.execute(
                    """
                    INSERT INTO trabajadores (dni, nombres, apellidos, tipo_trabajador)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (dni, nombres, apellidos, "DIGITADOR"),
                )

        conn.commit()
        conn.close()

        mensaje_ok = "Registro exitoso. Ya puedes iniciar sesión."
        return render_template("registro_usuario.html",
                               mensaje_ok=mensaje_ok)

    return render_template("registro_usuario.html")


# =========================================================
# Logout
# =========================================================

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# =========================================================
# Dashboard - redirección por rol
# =========================================================

@app.route("/dashboard")
def dashboard():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    rol = session.get("rol")

    if rol == "ADMIN":
        return redirect(url_for("admin_panel"))
    elif rol == "DIGITADOR":
        return redirect(url_for("digitador_panel"))
    else:
        return redirect(url_for("usuario_panel"))


# =========================================================
# Panel DIGITADOR
# =========================================================
@app.route("/digitador")
def digitador_panel():
    """
    Dashboard personal del DIGITADOR.
    - Estadísticas de las boletas que él/ella ha digitalizado (dni_digitador)
    - Listado filtrable de esas boletas (buscador + Año + Mes + Estado)
    """
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    if session.get("rol") != "DIGITADOR":
        return "Acceso no autorizado", 403

    dni = session.get("dni")

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Datos del trabajador (solo para mostrar nombre en encabezado)
    cur.execute(
        "SELECT id_trabajador, nombres, apellidos FROM trabajadores WHERE dni = %s",
        (dni,),
    )
    trabajador = cur.fetchone()

    # ==============================
    # Estadísticas del digitador
    # ==============================
    total_boletas = 0
    boletas_verificadas = 0
    boletas_pendientes = 0
    errores_carga = 0  # por ahora sin tabla de errores

    labels_anios = []
    data_total_por_anio = []
    data_verificadas_por_anio = []
    data_pct_verificadas_por_anio = []

    cur.execute(
        """
        SELECT
            anio,
            COUNT(*) AS total,
            SUM(CASE WHEN verificada THEN 1 ELSE 0 END) AS verificadas
        FROM boletas_historicas
        WHERE dni_digitador = %s
        GROUP BY anio
        ORDER BY anio
        """,
        (dni,),
    )
    rows = cur.fetchall()

    if rows:
        total_boletas = sum(r["total"] for r in rows)
        boletas_verificadas = sum((r["verificadas"] or 0) for r in rows)
        boletas_pendientes = total_boletas - boletas_verificadas

        for r in rows:
            labels_anios.append(str(r["anio"]))
            data_total_por_anio.append(r["total"])
            data_verificadas_por_anio.append(r["verificadas"] or 0)
            if r["total"] > 0:
                pct = round((r["verificadas"] or 0) * 100.0 / r["total"], 1)
            else:
                pct = 0.0
            data_pct_verificadas_por_anio.append(pct)

    # ==============================
    # Listado filtrable de boletas
    # ==============================
    q = (request.args.get("q") or "").strip()
    anio = (request.args.get("anio") or "").strip()
    mes = (request.args.get("mes") or "").strip()
    estado = (request.args.get("estado") or "").strip()

    where_clauses = ["b.dni_digitador = %s"]
    params = [dni]

    if q:
        like = f"%{q}%"
        where_clauses.append(
            "(t.dni ILIKE %s OR t.nombres ILIKE %s OR t.apellidos ILIKE %s)"
        )
        params.extend([like, like, like])

    if anio:
        where_clauses.append("b.anio = %s")
        params.append(int(anio))

    if mes:
        where_clauses.append("b.mes = %s")
        params.append(int(mes))

    if estado == "pendiente":
        where_clauses.append("b.verificada = FALSE")
    elif estado == "verificada":
        where_clauses.append("b.verificada = TRUE")

    where_sql = " AND ".join(where_clauses)

    cur.execute(
        f"""
        SELECT
            b.id_boleta,
            b.anio,
            b.mes,
            b.verificada,
            b.fuente,
            b.tiene_error,
            b.fecha_digitalizacion,
            t.dni,
            t.nombres,
            t.apellidos
        FROM boletas_historicas b
        JOIN trabajadores t ON t.id_trabajador = b.id_trabajador
        WHERE {where_sql}
        ORDER BY b.fecha_digitalizacion DESC NULLS LAST, b.id_boleta DESC
        """,
        params,
    )
    boletas = cur.fetchall()

    conn.close()

    return render_template(
        "digitador_panel.html",
        trabajador=trabajador,
        total_boletas=total_boletas,
        boletas_verificadas=boletas_verificadas,
        boletas_pendientes=boletas_pendientes,
        errores_carga=errores_carga,
        labels_anios=labels_anios,
        data_total_por_anio=data_total_por_anio,
        data_verificadas_por_anio=data_verificadas_por_anio,
        data_pct_verificadas_por_anio=data_pct_verificadas_por_anio,
        boletas=boletas,
        q=q,
        filtro_anio=anio,
        filtro_mes=mes,
        filtro_estado=estado,
    )


# =========================================================
# Panel del Usuario – ver sus boletas (como trabajador)
# =========================================================

@app.route("/usuario")
def usuario_panel():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    dni = session["dni"]

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Buscar trabajador por DNI
    cur.execute(
        "SELECT id_trabajador, nombres, apellidos FROM trabajadores WHERE dni = %s",
        (dni,),
    )
    trabajador = cur.fetchone()

    boletas = []

    if trabajador:
        cur.execute(
            """
            SELECT *
            FROM boletas_historicas
            WHERE id_trabajador = %s
            ORDER BY anio DESC, mes DESC
            """,
            (trabajador["id_trabajador"],),
        )
        boletas = cur.fetchall()

    conn.close()

    return render_template(
        "usuario_panel.html",
        boletas=boletas,
        trabajador=trabajador,
    )


# =========================================================
# Panel ADMIN – dashboard con métricas, gráficos y proyección
# =========================================================

@app.route("/admin")
def admin_panel():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    if session.get("rol") != "ADMIN":
        return "Acceso no autorizado", 403

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # ---------- métricas base ----------
    cur.execute("SELECT COUNT(*) FROM boletas_historicas")
    total_boletas = cur.fetchone()[0]

    cur.execute("SELECT COUNT(DISTINCT anio) FROM boletas_historicas")
    anios_cubiertos = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM trabajadores")
    total_trabajadores = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM boletas_historicas WHERE verificada = FALSE")
    pendientes_clasificar = cur.fetchone()[0]

    # ---------- métricas adicionales ----------
    cur.execute("SELECT COUNT(*) FROM boletas_historicas WHERE verificada = TRUE")
    verificadas = cur.fetchone()[0]

    cur.execute("SELECT MIN(anio), MAX(anio) FROM boletas_historicas")
    row_anios = cur.fetchone()
    anio_min, anio_max = row_anios if row_anios else (None, None)

    cur.execute("SELECT COUNT(DISTINCT id_trabajador) FROM boletas_historicas")
    trabajadores_con_boleta = cur.fetchone()[0]

    # funciones auxiliares
    def safe_pct(num, den):
        return round(num * 100.0 / den, 1) if den else 0.0

    porc_boletas_verificadas = safe_pct(verificadas, total_boletas)
    porc_pendientes = safe_pct(pendientes_clasificar, total_boletas)

    if anio_min is not None:
        total_anios_posibles = anio_max - anio_min + 1
        porc_cobertura_anios = safe_pct(anios_cubiertos, total_anios_posibles)
    else:
        porc_cobertura_anios = 0.0

    porc_trabajadores_cubiertos = safe_pct(trabajadores_con_boleta, total_trabajadores)

    # ---------- Datos para los gráficos ----------
    cur.execute("""
        SELECT anio,
               COUNT(*) AS total,
               SUM(CASE WHEN verificada THEN 1 ELSE 0 END) AS verificadas
        FROM boletas_historicas
        GROUP BY anio
        ORDER BY anio
    """)
    rows = cur.fetchall()

    labels_por_anio = [r["anio"] for r in rows]
    data_total_por_anio = [r["total"] for r in rows]
    data_verificadas_por_anio = [r["verificadas"] for r in rows]
    data_pct_verificadas_por_anio = [
        safe_pct(r["verificadas"], r["total"]) for r in rows
    ]

    # ---------- Proyección ----------
    ritmo_promedio_anual = round(
        total_boletas / anios_cubiertos, 2
    ) if anios_cubiertos > 0 else 0

    proyeccion_total_boletas_3_anios = int(
        total_boletas + ritmo_promedio_anual * 3
    )

    conn.close()

    return render_template(
        "admin_panel.html",

        # tarjetas
        total_boletas=total_boletas,
        anios_cubiertos=anios_cubiertos,
        total_trabajadores=total_trabajadores,
        pendientes_clasificar=pendientes_clasificar,
        porc_boletas_verificadas=porc_boletas_verificadas,
        porc_cobertura_anios=porc_cobertura_anios,
        porc_trabajadores_cubiertos=porc_trabajadores_cubiertos,
        porc_pendientes=porc_pendientes,
        anio_min=anio_min,
        anio_max=anio_max,

        # gráficos
        labels_por_anio=labels_por_anio,
        data_total_por_anio=data_total_por_anio,
        data_verificadas_por_anio=data_verificadas_por_anio,
        data_pct_verificadas_por_anio=data_pct_verificadas_por_anio,

        # proyecciones
        ritmo_promedio_anual=ritmo_promedio_anual,
        proyeccion_total_boletas_3_anios=proyeccion_total_boletas_3_anios,
    )


# =========================================================
# Gestión de Boletas (CRUD) - /admin/boletas
# =========================================================

@app.route("/admin/boletas")
def admin_boletas():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    if session.get("rol") != "ADMIN":
        return "Acceso no autorizado", 403

    # filtros
    q = request.args.get("q", "").strip()
    anio = request.args.get("anio", "").strip()
    mes = request.args.get("mes", "").strip()
    estado = request.args.get("estado", "").strip()
    # ahora el orden por defecto es "estado_desc" -> pendientes primero
    orden = request.args.get("orden", "estado_desc")

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # métricas simples para las tarjetas de arriba
    cur.execute("SELECT COUNT(*) FROM boletas_historicas")
    total_boletas = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM boletas_historicas WHERE verificada = TRUE")
    boletas_verificadas = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM boletas_historicas WHERE verificada = FALSE")
    boletas_pendientes = cur.fetchone()[0]

    errores_carga = 0  # por ahora fijo

    # WHERE dinámico
    where_clauses = []
    params = []

    if q:
        where_clauses.append(
            "(t.dni ILIKE %s OR t.nombres ILIKE %s OR t.apellidos ILIKE %s)"
        )
        like = f"%{q}%"
        params.extend([like, like, like])

    if anio:
        where_clauses.append("b.anio = %s")
        params.append(int(anio))

    if mes:
        where_clauses.append("b.mes = %s")
        params.append(int(mes))

    if estado == "pendiente":
        where_clauses.append("b.verificada = FALSE")
    elif estado == "verificada":
        where_clauses.append("b.verificada = TRUE")

    where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

        # ------ ORDEN ------
    # verificada = FALSE (0) -> pendientes
    # verificada = TRUE  (1) -> verificadas
    if orden == "anio_asc":
        order_sql = "ORDER BY b.anio ASC, b.mes ASC, t.apellidos"
    elif orden == "anio_desc":
        order_sql = "ORDER BY b.anio DESC, b.mes DESC, t.apellidos"
    elif orden == "estado_asc":
        # pendientes primero, luego verificadas
        order_sql = """
            ORDER BY
                b.verificada ASC,
                b.fecha_digitalizacion ASC NULLS LAST,
                t.apellidos
        """
    else:  # "estado_desc" por defecto -> pendientes primero, pero más reciente arriba
        order_sql = """
            ORDER BY
                b.verificada ASC,
                b.fecha_digitalizacion DESC NULLS LAST,
                t.apellidos
        """

    # consulta de boletas
    query = f"""
        SELECT b.*, t.nombres, t.apellidos, t.dni
        FROM boletas_historicas b
        JOIN trabajadores t ON t.id_trabajador = b.id_trabajador
        {where_sql}
        {order_sql}
    """
    cur.execute(query, params)
    boletas = cur.fetchall()

    conn.close()

    return render_template(
        "admin_boletas.html",
        boletas=boletas,
        total_boletas=total_boletas,
        boletas_verificadas=boletas_verificadas,
        boletas_pendientes=boletas_pendientes,
        errores_carga=errores_carga,
        q=q,
        filtro_anio=anio,
        filtro_mes=mes,
        filtro_estado=estado,
        orden=orden,
    )



# =========================================================
# GESTIÓN DE USUARIOS (ADMIN)
# =========================================================

@app.route("/admin/usuarios")
def admin_usuarios():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    if session.get("rol") != "ADMIN":
        return "Acceso no autorizado", 403

    rol_filtro = (request.args.get("rol") or "TODOS").upper()
    q = (request.args.get("q") or "").strip()

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    where_clauses = []
    params = []

    # Filtro por rol si es ADMIN / DIGITADOR / CONSULTA
    if rol_filtro in ("ADMIN", "DIGITADOR", "CONSULTA"):
        where_clauses.append("rol = %s")
        params.append(rol_filtro)

    # Buscador por DNI / nombres / apellidos
    if q:
        like = f"%{q}%"
        where_clauses.append("(dni ILIKE %s OR nombres ILIKE %s OR apellidos ILIKE %s)")
        params.extend([like, like, like])

    where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

    cur.execute(
        f"""
        SELECT id_usuario, dni, nombres, apellidos, rol, estado, correo
        FROM usuarios
        {where_sql}
        ORDER BY id_usuario
        """,
        params,
    )
    usuarios = cur.fetchall()
    conn.close()

    return render_template(
        "admin_usuarios.html",
        usuarios=usuarios,
        rol_filtro=rol_filtro,
        q=q,
    )


@app.route("/admin/usuarios/guardar", methods=["POST"])
def guardar_usuario():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    if session.get("rol") != "ADMIN":
        return "Acceso no autorizado", 403

    id_usuario = request.form.get("id_usuario")
    dni = (request.form.get("dni") or "").strip()
    rol = (request.form.get("rol") or "").strip().upper()
    nombres = (request.form.get("nombres") or "").strip()
    apellidos = (request.form.get("apellidos") or "").strip()
    correo = (request.form.get("correo") or "").strip()
    estado = (request.form.get("estado") or "A").strip().upper()

    if not dni or not rol or not nombres or not apellidos:
        flash("DNI, Rol, Nombres y Apellidos son obligatorios.", "danger")
        return redirect(url_for("admin_usuarios"))
    
    # NUEVO: validaciones de formato para el administrador
    if not validar_dni(dni):
        flash("El DNI debe tener exactamente 8 dígitos numéricos.", "danger")
        return redirect(url_for("admin_usuarios"))

    if not validar_nombre(nombres):
        flash("Los nombres solo deben contener letras y espacios.", "danger")
        return redirect(url_for("admin_usuarios"))

    if not validar_nombre(apellidos):
        flash("Los apellidos solo deben contener letras y espacios.", "danger")
        return redirect(url_for("admin_usuarios"))

    if not validar_correo(correo or ""):
        flash("El correo electrónico no tiene un formato válido.", "danger")
        return redirect(url_for("admin_usuarios"))


    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if id_usuario:  # EDITAR
        # Obtener rol anterior para saber si cambió a DIGITADOR
        cur.execute(
            "SELECT rol, dni FROM usuarios WHERE id_usuario = %s",
            (int(id_usuario),),
        )
        previo = cur.fetchone()
        rol_prev = previo["rol"] if previo else None

        cur.execute(
            """
            UPDATE usuarios
            SET dni = %s,
                nombres = %s,
                apellidos = %s,
                correo = %s,
                rol = %s,
                estado = %s
            WHERE id_usuario = %s
            """,
            (dni, nombres, apellidos, correo, rol, estado, int(id_usuario)),
        )

        # Si ahora es DIGITADOR y antes no lo era, asegurar trabajador
        if rol == "DIGITADOR" and rol_prev != "DIGITADOR":
            cur.execute(
                "SELECT id_trabajador FROM trabajadores WHERE dni = %s",
                (dni,),
            )
            trab = cur.fetchone()
            if not trab:
                cur.execute(
                    """
                    INSERT INTO trabajadores (dni, nombres, apellidos, tipo_trabajador)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (dni, nombres, apellidos, "DIGITADOR"),
                )

        flash("Usuario actualizado correctamente.", "success")

    else:  # NUEVO
        # Contraseña por defecto "123456" (hasheada)
        clave_por_defecto = "123456"
        hash_default = generate_password_hash(clave_por_defecto)
        cur.execute(
            """
            INSERT INTO usuarios (dni, nombres, apellidos, correo, rol, estado, clave_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (dni, nombres, apellidos, correo, rol, estado, hash_default),
        )

        # Si el nuevo usuario es DIGITADOR, crear también trabajador
        if rol == "DIGITADOR":
            cur.execute(
                "SELECT id_trabajador FROM trabajadores WHERE dni = %s",
                (dni,),
            )
            trab = cur.fetchone()
            if not trab:
                cur.execute(
                    """
                    INSERT INTO trabajadores (dni, nombres, apellidos, tipo_trabajador)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (dni, nombres, apellidos, "DIGITADOR"),
                )

        flash("Usuario creado correctamente (clave por defecto 123456).", "success")

    conn.commit()
    conn.close()

    return redirect(url_for("admin_usuarios", rol=rol if rol else None))


@app.route("/admin/usuarios/<int:id_usuario>/baja", methods=["POST"])
def dar_baja_usuario(id_usuario):
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    if session.get("rol") != "ADMIN":
        return "Acceso no autorizado", 403

    conn = get_db()
    cur = conn.cursor()
    # Solo marcamos como inactivo, no borramos el registro
    cur.execute(
        "UPDATE usuarios SET estado = 'I' WHERE id_usuario = %s",
        (id_usuario,),
    )
    conn.commit()
    conn.close()

    # Mantener el filtro de rol si venía en la URL
    rol = request.args.get("rol")
    if rol:
        return redirect(url_for("admin_usuarios", rol=rol))
    return redirect(url_for("admin_usuarios"))


# =========================================================
# Toggle estado verificada/pendiente
# =========================================================

# =========================================================
# Helpers de permisos para ver boletas
# =========================================================

def _puede_ver_boleta(fila_boleta, rol, dni_sesion):
    """
    fila_boleta: DictRow con campos
      - dni_titular
      - dni_digitador
    """
    if rol == "ADMIN":
        return True

    dni_titular = fila_boleta.get("dni_titular")
    dni_digitador = fila_boleta.get("dni_digitador")

    if rol == "DIGITADOR":
        # Puede ver sus propias boletas como trabajador
        # o boletas que él mismo digitalizó
        return dni_sesion == dni_titular or dni_sesion == dni_digitador

    # CONSULTA u otro rol: solo sus propias boletas
    return dni_sesion == dni_titular


# =========================================================
# Detalle boleta (con control de permisos)
# =========================================================

@app.route("/boleta/<int:id_boleta>")
def detalle_boleta(id_boleta: int):
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    rol = session.get("rol")
    dni_sesion = session.get("dni")

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(
        """
        SELECT
            b.*,
            t.dni AS dni_titular,
            t.nombres AS nombres_titular,
            t.apellidos AS apellidos_titular,
            t.tipo_trabajador,
            u.nombres AS nombres_digitador,
            u.apellidos AS apellidos_digitador
        FROM boletas_historicas b
        JOIN trabajadores t ON t.id_trabajador = b.id_trabajador
        LEFT JOIN usuarios u ON u.dni = b.dni_digitador
        WHERE b.id_boleta = %s
        """,
        (id_boleta,),
    )
    boleta = cur.fetchone()
    conn.close()

    if not boleta:
        return "Boleta no encontrada", 404

    # _puede_ver_boleta usa dni_titular y dni_digitador
    if not _puede_ver_boleta(boleta, rol, dni_sesion):
        return "No tienes permiso para ver esta boleta.", 403

    meses = [
        "Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio",
        "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre"
    ]
    mes_texto = meses[boleta["mes"] - 1]

    return render_template("detalle_boleta.html", boleta=boleta, mes_texto=mes_texto)


# =========================================================
# Descargar boleta (con control de permisos)
# =========================================================

@app.route("/descargar/<int:id_boleta>")
def descargar_boleta(id_boleta: int):
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    rol = session.get("rol")
    dni_sesion = session.get("dni")

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(
        """
        SELECT
            b.ruta_archivo,
            b.dni_digitador,
            t.dni AS dni_titular
        FROM boletas_historicas b
        JOIN trabajadores t ON t.id_trabajador = b.id_trabajador
        WHERE b.id_boleta = %s
        """,
        (id_boleta,),
    )
    fila = cur.fetchone()
    conn.close()

    if not fila:
        return "Boleta no encontrada", 404

    if not _puede_ver_boleta(fila, rol, dni_sesion):
        return "No tienes permiso para descargar esta boleta.", 403

    ruta = fila["ruta_archivo"]
    if not os.path.exists(ruta):
        return "Archivo de boleta no encontrado en el servidor.", 404

    return send_file(ruta, as_attachment=True)


# =========================================================
# Ver PDF inline (con control de permisos)
# =========================================================

@app.route("/boleta/pdf/<int:id_boleta>")
def ver_pdf_boleta(id_boleta: int):
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    rol = session.get("rol")
    dni_sesion = session.get("dni")

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(
        """
        SELECT
            b.ruta_archivo,
            b.dni_digitador,
            t.dni AS dni_titular
        FROM boletas_historicas b
        JOIN trabajadores t ON t.id_trabajador = b.id_trabajador
        WHERE b.id_boleta = %s
        """,
        (id_boleta,),
    )
    fila = cur.fetchone()
    conn.close()

    if not fila:
        return "Boleta no encontrada", 404

    if not _puede_ver_boleta(fila, rol, dni_sesion):
        return "No tienes permiso para ver esta boleta.", 403

    ruta = fila["ruta_archivo"]
    if not os.path.exists(ruta):
        return "Archivo de boleta no encontrado en el servidor.", 404

    return send_file(ruta, as_attachment=False)


# =========================================================
# Toggle estado verificada/pendiente (ADMIN)
# =========================================================

@app.route("/admin/boletas/<int:id_boleta>/toggle")
def toggle_estado(id_boleta: int):
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    if session.get("rol") != "ADMIN":
        return "Acceso no autorizado", 403

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    # Cambiamos TRUE/FALSE por el contrario
    cur.execute(
        """
        UPDATE boletas_historicas
        SET verificada = NOT verificada
        WHERE id_boleta = %s
        RETURNING verificada
        """,
        (id_boleta,),
    )
    conn.commit()
    conn.close()

    return redirect(url_for("admin_boletas"))


# =========================================================
# Subir Boletas (solo DIGITADOR)
# =========================================================

@app.route("/digitador/subir_boletas", methods=["GET", "POST"])
def subir_boletas():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    if session.get("rol") != "DIGITADOR":
        return "Acceso no autorizado", 403

    digitador_dni = session.get("dni")

    # valores por defecto para rellenar el formulario
        # valores por defecto para rellenar el formulario
    contexto_form = {
        "anio_form": "",
        "mes_form": "",
        "dni_titular_form": "",
        "caja_form": "",
        "legajo_form": "",
        "carpeta_form": "",
        "regimen_cargo_form": "",
        "nombre_archivo": "",
    }



    if request.method == "POST":
        archivo = request.files.get("archivo")
        anio = (request.form.get("anio") or "").strip()
        mes = (request.form.get("mes") or "").strip()
        dni_titular = (request.form.get("dni_titular") or "").strip()
        nombres_titular = (request.form.get("nombres_titular") or "").strip()
        apellidos_titular = (request.form.get("apellidos_titular") or "").strip()

        # OJO: guardamos los valores "raw" para validar y luego convertimos a None si están vacíos
        caja_raw = (request.form.get("caja_fisica") or "").strip()
        legajo_raw = (request.form.get("legajo_fisico") or "").strip()
        carpeta_raw = (request.form.get("carpeta_fisica") or "").strip()

        caja_fisica = caja_raw or None
        legajo_fisico = legajo_raw or None
        carpeta_fisica = carpeta_raw or None

        tipo_trabajador = (request.form.get("tipo_trabajador") or "").strip() or None
        regimen_cargo = (request.form.get("regimen_cargo") or "").strip() or None
        if not tipo_trabajador:
            tipo_trabajador = "NO_REGISTRADO"


        # guardar lo que el usuario ya escribió
                # guardar lo que el usuario ya escribió
        contexto_form.update({
            "anio_form": anio,
            "mes_form": mes,
            "dni_titular_form": dni_titular,
            "nombres_titular_form": nombres_titular,
            "apellidos_titular_form": apellidos_titular,
            "caja_form": caja_raw,
            "legajo_form": legajo_raw,
            "carpeta_form": carpeta_raw,
            "tipo_trabajador_form": tipo_trabajador or "",
            "regimen_cargo_form": regimen_cargo or "",
        })



        # Validaciones
        if not archivo or archivo.filename == "":
            flash("Debes seleccionar un archivo.", "danger")
            return render_template(
                "subir_boletas.html",
                digitador_dni=digitador_dni,
                **contexto_form,
            )

        if not allowed_file(archivo.filename):
            flash("Solo se permiten archivos PDF o ZIP.", "danger")
            contexto_form["nombre_archivo"] = archivo.filename
            return render_template(
                "subir_boletas.html",
                digitador_dni=digitador_dni,
                **contexto_form,
            )

        if not anio or not mes:
            flash("Selecciona año y mes.", "danger")
            contexto_form["nombre_archivo"] = archivo.filename
            return render_template(
                "subir_boletas.html",
                digitador_dni=digitador_dni,
                **contexto_form,
            )

        if not nombres_titular or not apellidos_titular:
            flash("Debes ingresar nombres y apellidos del titular.", "danger")
            contexto_form["nombre_archivo"] = archivo.filename
            return render_template(
                "subir_boletas.html",
                digitador_dni=digitador_dni,
                **contexto_form,
            )
        
        # NUEVO: Validar formatos de datos
        if not validar_dni(dni_titular):
            flash("El DNI del titular debe tener exactamente 8 dígitos numéricos.", "danger")
            contexto_form["nombre_archivo"] = archivo.filename if archivo else ""
            return render_template(
                "subir_boletas.html",
                digitador_dni=digitador_dni,
                **contexto_form,
            )

        if not validar_nombre(nombres_titular):
            flash("Los nombres del titular solo deben contener letras y espacios.", "danger")
            contexto_form["nombre_archivo"] = archivo.filename if archivo else ""
            return render_template(
                "subir_boletas.html",
                digitador_dni=digitador_dni,
                **contexto_form,
            )

        if not validar_nombre(apellidos_titular):
            flash("Los apellidos del titular solo deben contener letras y espacios.", "danger")
            contexto_form["nombre_archivo"] = archivo.filename if archivo else ""
            return render_template(
                "subir_boletas.html",
                digitador_dni=digitador_dni,
                **contexto_form,
            )

        if not validar_anio(anio) or not validar_mes(mes):
            flash("El año o el mes no son válidos.", "danger")
            contexto_form["nombre_archivo"] = archivo.filename if archivo else ""
            return render_template(
                "subir_boletas.html",
                digitador_dni=digitador_dni,
                **contexto_form,
            )

        # caja / legajo / carpeta son opcionales pero con caracteres controlados
        if not validar_caja_legajo_carpeta(caja_raw):
            flash("La caja física contiene caracteres no permitidos.", "danger")
            contexto_form["nombre_archivo"] = archivo.filename if archivo else ""
            return render_template(
                "subir_boletas.html",
                digitador_dni=digitador_dni,
                **contexto_form,
            )

        if not validar_caja_legajo_carpeta(legajo_raw):
            flash("El legajo físico contiene caracteres no permitidos.", "danger")
            contexto_form["nombre_archivo"] = archivo.filename if archivo else ""
            return render_template(
                "subir_boletas.html",
                digitador_dni=digitador_dni,
                **contexto_form,
            )

        if not validar_caja_legajo_carpeta(carpeta_raw):
            flash("La carpeta física contiene caracteres no permitidos.", "danger")
            contexto_form["nombre_archivo"] = archivo.filename if archivo else ""
            return render_template(
                "subir_boletas.html",
                digitador_dni=digitador_dni,
                **contexto_form,
            )



        try:
            anio_int = int(anio)
            mes_int = int(mes)
        except ValueError:
            flash("Año o mes inválidos.", "danger")
            contexto_form["nombre_archivo"] = archivo.filename
            return render_template(
                "subir_boletas.html",
                digitador_dni=digitador_dni,
                **contexto_form,
            )

        # Guardar archivo
        filename = secure_filename(archivo.filename)
        ruta_guardado = os.path.join(UPLOAD_FOLDER, filename)
        archivo.save(ruta_guardado)
        contexto_form["nombre_archivo"] = filename

        # BD
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # trabajador titular (si existe, usamos nombres reales;
        # si no, creamos registro nuevo y guardamos el régimen/cargo)
        cur.execute(
            "SELECT id_trabajador, tipo_trabajador FROM trabajadores WHERE dni = %s",
            (dni_titular,),
        )
        trabajador = cur.fetchone()

        if trabajador:
            id_trabajador = trabajador["id_trabajador"]

            # Si escribieron un régimen/cargo y el que hay es vacío o NO_REGISTRADO, lo actualizamos
            if regimen_cargo and (trabajador["tipo_trabajador"] in (None, "", "NO_REGISTRADO")):
                cur.execute(
                    """
                    UPDATE trabajadores
                    SET tipo_trabajador = %s
                    WHERE id_trabajador = %s
                    """,
                    (regimen_cargo, id_trabajador),
                )
        else:
            tipo_trabajador_val = regimen_cargo or "NO_REGISTRADO"
            cur.execute(
                """
                INSERT INTO trabajadores (dni, nombres, apellidos, tipo_trabajador)
                VALUES (%s, %s, %s, %s)
                RETURNING id_trabajador
                """,
                (dni_titular, "SIN_NOMBRE", "SIN_NOMBRE", tipo_trabajador_val),
            )
            id_trabajador = cur.fetchone()["id_trabajador"]


        # Insert / upsert boleta
        cur.execute(
            """
            INSERT INTO boletas_historicas (
                id_trabajador, anio, mes,
                nombre_archivo, ruta_archivo,
                fuente, id_carga,
                caja_fisica, legajo_fisico, carpeta_fisica,
                verificada,
                dni_digitador,
                tiene_error
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (id_trabajador, anio, mes)
            DO UPDATE SET
                nombre_archivo       = EXCLUDED.nombre_archivo,
                ruta_archivo         = EXCLUDED.ruta_archivo,
                fuente               = EXCLUDED.fuente,
                id_carga             = EXCLUDED.id_carga,
                caja_fisica          = EXCLUDED.caja_fisica,
                legajo_fisico        = EXCLUDED.legajo_fisico,
                carpeta_fisica       = EXCLUDED.carpeta_fisica,
                fecha_digitalizacion = NOW(),
                verificada           = FALSE,
                dni_digitador        = EXCLUDED.dni_digitador,
                tiene_error          = FALSE
            """,
            (
                id_trabajador,
                anio_int,
                mes_int,
                filename,
                ruta_guardado,
                "ESCANEADA",
                None,
                caja_fisica,
                legajo_fisico,
                carpeta_fisica,
                False,
                digitador_dni,
                False,
            ),
        )

        conn.commit()
        conn.close()

        flash(
            f"Boleta subida correctamente. Titular DNI {dni_titular}, digitalizada por {digitador_dni}.",
            "success",
        )
        return redirect(url_for("digitador_panel"))

    # GET
    return render_template(
        "subir_boletas.html",
        digitador_dni=digitador_dni,
        **contexto_form,
    )


# =========================================================
# Run
# =========================================================

if __name__ == "__main__":
    app.run(debug=True)

