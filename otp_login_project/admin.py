import sqlite3
import sys
import datetime

DB_PATH = "database_fixed.db"

# -------------------------
# Funciones de base de datos
# -------------------------

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# 🔄 Registrar intento de login
import datetime

def registrar_intento(phone, ip=None):
    if ip is None:
        ip = 'Desconocida'

    ahora = datetime.datetime.now()  # hora local
    hora_actual = ahora.hour

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT attempts FROM login_attempts WHERE phone = ?", (phone,))
    row = cursor.fetchone()

    if row:
        attempts = row["attempts"] + 1
        cursor.execute(
            """UPDATE login_attempts 
               SET attempts = ?, last_attempt = ?, ip = ?, attempt_hour = ?
               WHERE phone = ?""",
            (attempts, ahora.strftime("%Y-%m-%d %H:%M:%S"), ip, hora_actual, phone)
        )
    else:
        cursor.execute(
            """INSERT INTO login_attempts (phone, attempts, last_attempt, ip, attempt_hour) 
               VALUES (?, 1, ?, ?, ?)""",
            (phone, ahora.strftime("%Y-%m-%d %H:%M:%S"), ip, hora_actual)
        )

    conn.commit()
    conn.close()


# 🔎 Ver intentos fallidos (sin pandas)
def verificar_intentos(phone: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM login_attempts WHERE phone = ?", (phone,))
    rows = cursor.fetchall()
    conn.close()

    if rows:
        print("ID | Phone | Attempts | Last Attempt | IP | Hour")
        for r in rows:
            print(f"{r['id']} | {r['phone']} | {r['attempts']} | {r['last_attempt']} | {r['ip']} | {r['attempt_hour']}")
    else:
        print(f"No hay intentos registrados para {phone}")

# 🔄 Resetear intentos fallidos
def resetear_intentos(phone: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE login_attempts SET attempts = 0 WHERE phone = ?", (phone,))
    conn.commit()
    if cursor.rowcount > 0:
        print(f"Se han reseteado los intentos fallidos para {phone}.")
    else:
        print(f"No había registros de intentos para {phone}.")
    conn.close()

# ➕ Crear invitación
def crear_invitacion(codigo: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO invitations (code) VALUES (?)", (codigo,))
        conn.commit()
        print(f"Invitación creada: {codigo}")
    except sqlite3.IntegrityError:
        print(f"El código '{codigo}' ya existe.")
    finally:
        conn.close()

# 📋 Listar todas las invitaciones
def listar_invitaciones():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, code FROM invitations")
    rows = cursor.fetchall()
    conn.close()

    if rows:
        print("ID | Código")
        for r in rows:
            print(f"{r['id']} | {r['code']}")
    else:
        print("No hay invitaciones registradas.")

# ❌ Eliminar una invitación
def eliminar_invitacion(codigo: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM invitations WHERE code = ?", (codigo,))
    conn.commit()
    if cursor.rowcount > 0:
        print(f"Invitación '{codigo}' eliminada.")
    else:
        print(f"No existe la invitación '{codigo}'.")
    conn.close()

# -------------------------
# CLI
# -------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso:")
        print("  python admin.py verificar <telefono>")
        print("  python admin.py reset <telefono>")
        print("  python admin.py invitacion <CODIGO>")
        print("  python admin.py listar_invitaciones")
        print("  python admin.py eliminar_invitacion <CODIGO>")
        sys.exit(1)

    accion = sys.argv[1].lower()

    if accion == "verificar" and len(sys.argv) == 3:
        verificar_intentos(sys.argv[2])
    elif accion == "reset" and len(sys.argv) == 3:
        resetear_intentos(sys.argv[2])
    elif accion == "invitacion" and len(sys.argv) == 3:
        crear_invitacion(sys.argv[2])
    elif accion == "listar_invitaciones":
        listar_invitaciones()
    elif accion == "eliminar_invitacion" and len(sys.argv) == 3:
        eliminar_invitacion(sys.argv[2])
    else:
        print("Comando no válido o parámetros faltantes.")
