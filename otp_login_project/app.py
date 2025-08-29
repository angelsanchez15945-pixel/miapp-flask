from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response
import sqlite3, os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "una_clave_super_segura_123_2025_only")
DATABASE = os.path.join(os.path.dirname(__file__), 'database_fixed.db')

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'comprobantes')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.permanent_session_lifetime = timedelta(days=7)
PING_INTERVAL = 5  # segundos
PING_TIMEOUT = 5   # segundos

PUBLIC_ROUTES = ['/', '/register', '/login1', '/static/', '/favicon.ico']

# ---------------- DB ----------------
def get_db_connection():
    conn = sqlite3.connect(DATABASE, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db_connection() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS usuarios_saldo (
            user_id INTEGER PRIMARY KEY,
            saldo REAL DEFAULT 6,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """)
        conn.execute("""
        INSERT OR IGNORE INTO usuarios_saldo (user_id, saldo)
        SELECT id, 6 FROM users
        """)
        conn.commit()
init_db()

# ---------------- UTIL ----------------
def get_user(username=None, user_id=None):
    query, param = ("username = ?", username) if username else ("id = ?", user_id)
    with get_db_connection() as conn:
        user = conn.execute(f"SELECT * FROM users WHERE {query}", (param,)).fetchone()
    return user

def get_saldo(username):
    user = get_user(username=username)
    if user:
        return obtener_saldo(user['id'])
    return 0

def obtener_saldo(user_id):
    with get_db_connection() as conn:
        fila = conn.execute("SELECT saldo FROM usuarios_saldo WHERE user_id=?", (user_id,)).fetchone()
        if fila:
            return fila['saldo']
        else:
            conn.execute("INSERT INTO usuarios_saldo (user_id, saldo) VALUES (?, ?)", (user_id, 6))
            conn.commit()
            return 6

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

from datetime import datetime, timedelta

def asignar_pedidos_desde_base(conn, username, vip_nivel):
    pedidos_base = conn.execute("""
        SELECT nombre, monto, total, comision, imagen, fecha_limite, descripcion
        FROM pedidos 
        WHERE username IS NULL AND vip_nivel=? LIMIT 6
    """, (vip_nivel,)).fetchall()
    
    for p in pedidos_base:
        imagen = p['imagen'] if p['imagen'] and p['imagen'].startswith('http') else f"static/img_pedidos/{p['imagen']}"

        # Convertir fecha con microsegundos si existe
        if p['fecha_limite']:
            try:
                fecha_base = datetime.strptime(p['fecha_limite'], "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                fecha_base = datetime.strptime(p['fecha_limite'], "%Y-%m-%d %H:%M:%S")
            nueva_fecha = fecha_base + timedelta(hours=1)
            fecha_limite = nueva_fecha.strftime("%Y-%m-%d %H:%M:%S")
        else:
            fecha_limite = (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")

        conn.execute("""
            INSERT INTO pedidos (username, nombre, monto, total, comision, estado, imagen, fecha_limite, vip_nivel, descripcion)
            VALUES (?, ?, ?, ?, ?, 'Pendiente', ?, ?, ?, ?)
        """, (username, p['nombre'], p['monto'], p['total'], p['comision'], imagen, fecha_limite, vip_nivel, p['descripcion']))
    
    conn.commit()


def registrar_intento(phone, ip):
    ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection() as conn:
        fila = conn.execute("SELECT * FROM login_attempts WHERE phone=?", (phone,)).fetchone()
        if fila:
            intentos = fila['attempts'] + 1
            conn.execute("""
                UPDATE login_attempts 
                SET attempts=?, last_attempt=?, ip=?, attempt_hour=?
                WHERE phone=?
            """, (intentos, ahora, ip, datetime.now().hour, phone))
        else:
            conn.execute("""
                INSERT INTO login_attempts (phone, attempts, last_attempt, ip, attempt_hour)
                VALUES (?, 1, ?, ?, ?)
            """, (phone, ahora, ip, datetime.now().hour))
        conn.commit()

# ---------------- DECORATORS ----------------
def user_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if str(session.get('is_admin')) in ["1", "98C12345P"]:
            flash("No tienes permiso para acceder a esta página", "error")
            return redirect(url_for('admin'))  # redirige a admin si es admin
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Debes iniciar sesión para acceder a esta página", "error")
            return redirect(url_for('login1'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or str(session.get('is_admin')) not in ["1", "98C12345P"]:
            flash("No tienes permisos de administrador", "error")
            return redirect(url_for('inicio'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------- BEFORE REQUEST ----------------
@app.before_request
def proteger_rutas_y_sesion():
    PUBLIC_ROUTES = [
        '/', '/register', '/login1', '/static/', '/favicon.ico'
    ]

    # Permitir rutas públicas sin login
    if any(request.path.startswith(r) for r in PUBLIC_ROUTES):
        return None

    ahora = datetime.now().timestamp()

    # ---------------- LOGIN OBLIGATORIO ----------------
    if 'username' not in session:
        flash("Debes iniciar sesión para acceder a esta página", "error")
        resp = make_response(redirect(url_for('login1')))
        resp.set_cookie('session', '', expires=0)
        return resp

    # ---------------- TIMEOUT SESIÓN ----------------
    ultimo = session.get('ultimo_acceso', ahora)
    if ahora - ultimo > 4*60:  # 4 minutos
        user_id = session.get('user_id')
        if user_id:
            with get_db_connection() as conn:
                conn.execute("UPDATE users SET is_online=0 WHERE id=?", (user_id,))
                conn.commit()
        session.clear()
        flash("Tu sesión expiró", "error")
        resp = make_response(redirect(url_for('logout')))
        resp.set_cookie('session', '', expires=0)
        return resp
    session['ultimo_acceso'] = ahora

    # ---------------- RUTAS ADMIN ----------------
    if request.path.startswith('/admin'):
        # Solo admin puede acceder
        if str(session.get('is_admin')) not in ["1", "98C12345P"]:
            flash("Debes ser administrador para acceder", "error")
            return redirect(url_for('logout'))

        # Expiración sesión admin 30 min
        ultimo_admin = session.get('ultimo_acceso_admin', ahora)
        if ahora - ultimo_admin > 30*60:
            session.clear()
            flash("Sesión de administrador expirada", "error")
            return redirect(url_for('logout'))

        # Bloqueo por IP
        ip_actual = request.remote_addr
        if session.get('admin_ip') and session['admin_ip'] != ip_actual:
            session.clear()
            flash("IP no autorizada para esta sesión admin", "error")
            return redirect(url_for('login1'))

        # Guardar timestamp e IP
        session['ultimo_acceso_admin'] = ahora
        if 'admin_ip' not in session:
            session['admin_ip'] = ip_actual

    # ---------------- BLOQUEO DE RUTAS NO REGISTRADAS ----------------
    rutas_validas = [
        '/', '/login1', '/register', '/inicio', '/pedido', '/mision', '/recarga', '/recarga2',
        '/procesar_recarga', '/yo', '/modificar_password', '/retiro', '/procesar_retiro',
        '/informe', '/historial_recarga', '/historial_retiro', '/detalles', '/idioma',
        '/mensajes', '/tarjeta', '/guardar_tarjeta', '/mejorar_vip',
        '/admin', '/admin/ping', '/admin/usuarios_conectados', '/admin/admins_conectados',
        '/admin/recargas', '/admin/retiros', '/admin/intentos', '/admin/intrusos',
        '/admin/aprobar_recarga', '/admin/rechazar_recarga',
        '/admin/aprobar_retiro', '/admin/rechazar_retiro',
        '/logout', '/user/ping', '/api/enviar_pedido', '/api/congelar_pedido'
    ]

    if not any(request.path.startswith(r) for r in rutas_validas):
        return "Acceso denegado", 403


# ---------------- PING ----------------
@app.route('/admin/ping', methods=['POST'])
@admin_required
def admin_ping():
    user_id = session.get('user_id')
    if user_id:
        with get_db_connection() as conn:
            conn.execute("UPDATE users SET last_ping=? WHERE id=?", (datetime.now(), user_id))
            conn.commit()
    return jsonify({"status": "ok"})

@app.route('/user/ping', methods=['POST'])
@login_required
def user_ping():
    user_id = session.get('user_id')
    if user_id:
        with get_db_connection() as conn:
            conn.execute("UPDATE users SET last_ping=? WHERE id=?", (datetime.now(), user_id))
            conn.commit()
    return jsonify({"status":"ok"})


# ---------------- LOGIN / REGISTRO ----------------
@app.route('/')
def index(): return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    alerta = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '').strip()
        invite_code = request.form.get('invite_code', '').strip()

        # 1️⃣ Validar campos completos
        if not (username and phone and password and invite_code):
            alerta = {
                "tipo": "error",
                "titulo": "Campos incompletos",
                "mensaje": "Completa todos los campos"
            }
            return render_template('register.html', alerta=alerta)

        with get_db_connection() as conn:
            try:
                # 2️⃣ Validar invitación
                invitation = conn.execute(
                    "SELECT * FROM invitations WHERE code=?",
                    (invite_code,)
                ).fetchone()
                if not invitation:
                    alerta = {
                        "tipo": "error",
                        "titulo": "Invitación inválida",
                        "mensaje": "Código de invitación inválido"
                    }
                    return render_template('register.html', alerta=alerta)

                # 3️⃣ Validar duplicados
                existing_user = conn.execute(
                    "SELECT * FROM users WHERE phone=? OR username=?",
                    (phone, username)
                ).fetchone()
                if existing_user:
                    alerta = {
                        "tipo": "error",
                        "titulo": "Usuario o teléfono ya registrado",
                        "mensaje": "El nombre de usuario o el teléfono ya están registrados"
                    }
                    return render_template('register.html', alerta=alerta)

                # 4️⃣ Insertar usuario de forma segura
                hashed = generate_password_hash(password)
                conn.execute(
                    "INSERT INTO users (username, phone, password, invite_code, vip_nivel) VALUES (?,?,?,?,?)",
                    (username, phone, hashed, invite_code, 1)
                )
                conn.commit()

                alerta = {
                    "tipo": "success",
                    "titulo": "Registro exitoso",
                    "mensaje": "Usuario registrado correctamente"
                }
            except sqlite3.IntegrityError as e:
                conn.rollback()  # ❌ Evita guardado parcial
                alerta = {
                    "tipo": "error",
                    "titulo": "Error de registro",
                    "mensaje": f"Ocurrió un error al registrar el usuario: {str(e)}"
                }
            except Exception as e:
                conn.rollback()
                alerta = {
                    "tipo": "error",
                    "titulo": "Error inesperado",
                    "mensaje": f"Algo salió mal: {str(e)}"
                }

    return render_template('register.html', alerta=alerta)


@app.route('/login1', methods=['GET', 'POST'])
def login1():
    if request.method == 'POST':
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '').strip()
        ip = request.remote_addr or "Desconocida"

        if not phone or not password:
            flash('Completa ambos campos', 'error')
            return render_template('login1.html')

        with sqlite3.connect(DATABASE, timeout=10, check_same_thread=False) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            user = cursor.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()

            # Control de fuerza bruta
            if user and str(user['is_admin']) in ["0", ""]:
                intento = cursor.execute("SELECT attempts, last_attempt FROM login_attempts WHERE phone=?", (phone,)).fetchone()
                if intento:
                    last_time = datetime.strptime(intento['last_attempt'], "%Y-%m-%d %H:%M:%S")
                    if intento['attempts'] >= 5 and datetime.now() - last_time < timedelta(minutes=5):
                        flash('Demasiados intentos. Espera 5 minutos', 'error')
                        return render_template('login1.html')

            # Validar usuario y contraseña
            if user:
                # ✅ Control sesión única: permitir login si usuario offline o inactivo > X min
                if user['is_online'] == 1:
                    last_ping = user['last_ping']
                    if last_ping:
                        last_ping_dt = datetime.strptime(last_ping, "%Y-%m-%d %H:%M:%S.%f")
                        if datetime.now() - last_ping_dt < timedelta(minutes=5):
                            flash('Este usuario ya está conectado en otro navegador/dispositivo.', 'error')
                            return render_template('login1.html')
                    # si el ping fue hace más de 5 minutos, permitimos reconexión
                    cursor.execute("UPDATE users SET is_online=0 WHERE id=?", (user['id'],))
                    conn.commit()

                if check_password_hash(user['password'], password):
                    # Limpiar intentos
                    if str(user['is_admin']) in ["0", ""]:
                        cursor.execute("DELETE FROM login_attempts WHERE phone=?", (phone,))
                        conn.commit()

                    # Marcar usuario online
                    cursor.execute("UPDATE users SET is_online=1, last_ping=? WHERE id=?", (datetime.now(), user['id']))
                    conn.commit()

                    # Iniciar sesión
                    session.permanent = True
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['is_admin'] = user['is_admin'] or "0"
                    session['saldo'] = obtener_saldo(user['id'])
                    flash('Inicio de sesión exitoso', 'success')

                    return redirect(url_for('admin')) if str(user['is_admin']) in ["1", "98C12345P"] else redirect(url_for('inicio'))

            # Registrar intento fallido
            registrar_intento(phone, ip)
            flash('Teléfono o contraseña incorrectos', 'error')
            return render_template('login1.html')

    return render_template('login1.html')








# ---------------- INICIO ----------------
@app.route('/inicio')
@login_required
@user_required
def inicio():
    username = session['username']
    saldo = get_saldo(username)
    user = get_user(username=username)
    numero_trabajo = f"{user['id']:06d}" if user else "000000"
    fecha_actual = datetime.now().strftime("%d-%m")
    return render_template('inicio.html', numero_trabajo=numero_trabajo, saldo=saldo, fecha_actual=fecha_actual)

# ---------------- PEDIDOS ----------------
@app.route('/pedido')
@login_required
@user_required
def pedido():
    username = session['username']
    saldo = get_saldo(username)
    filtro = request.args.get('filtro','todos')

    with get_db_connection() as conn:
        total_pedidos_usuario = conn.execute("SELECT COUNT(*) FROM pedidos WHERE username=?", (username,)).fetchone()[0]
        if total_pedidos_usuario == 0:
            vip_nivel = conn.execute("SELECT vip_nivel FROM users WHERE username=?", (username,)).fetchone()['vip_nivel']
            asignar_pedidos_desde_base(conn, username, vip_nivel)

        query = "SELECT * FROM pedidos WHERE username=?"
        params = [username]
        if filtro=='pendiente': query+=" AND estado='Pendiente'"
        elif filtro=='congelado': query+=" AND estado='Congelado'"
        elif filtro=='completado': query+=" AND estado='Completado'"
        query+=" ORDER BY id DESC"

        pedidos = conn.execute(query, params).fetchall()
        total_pedidos = conn.execute("SELECT COUNT(*) FROM pedidos WHERE username=?", (username,)).fetchone()[0]
        completados = conn.execute("SELECT COUNT(*) FROM pedidos WHERE username=? AND estado='Completado'", (username,)).fetchone()[0]

    progreso = (completados/total_pedidos)*100 if total_pedidos>0 else 0
    return render_template('pedido.html', saldo=saldo, pedidos=pedidos, filtro=filtro,
                           total_pedidos=total_pedidos, completados=completados, progreso=progreso)






# ---------------- API PEDIDOS ----------------
@app.route('/api/enviar_pedido', methods=['POST'])
@login_required
@user_required
def enviar_pedido():
    try:
        # Obtener datos del pedido y usuario
        data = request.get_json()
        pedido_id = data.get("id")
        user_id = session.get("user_id")  # ID del usuario logueado

        if not user_id:
            return jsonify({"mensaje": "no_autenticado"}), 401

        conn = sqlite3.connect(DATABASE, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Traer monto y comisión del pedido
        cursor.execute("SELECT monto, comision, estado FROM pedidos WHERE id=? AND username=?", (pedido_id, session['username']))
        pedido = cursor.fetchone()
        if not pedido:
            conn.close()
            return jsonify({"mensaje": "pedido_no_encontrado"}), 400

        if pedido['estado'] == "Completado":
            conn.close()
            return jsonify({"mensaje": "pedido_ya_completado"}), 400

        saldo_actual = cursor.execute("SELECT saldo FROM usuarios_saldo WHERE user_id=?", (user_id,)).fetchone()['saldo']

        # Verificar si hay saldo suficiente
        if saldo_actual < pedido['monto']:
            conn.close()
            return jsonify({"mensaje": "saldo_insuficiente"}), 400

        # Actualizar saldo sumando la comisión
        nuevo_saldo = saldo_actual + pedido['comision']
        cursor.execute("UPDATE usuarios_saldo SET saldo=? WHERE user_id=?", (nuevo_saldo, user_id))

        # Marcar pedido como completado
        cursor.execute("UPDATE pedidos SET estado='Completado' WHERE id=? AND username=?", (pedido_id, session['username']))

        conn.commit()
        conn.close()

        return jsonify({"mensaje": "ok", "nuevo_saldo": nuevo_saldo}), 200

    except Exception as e:
        print(f"❌ ERROR en /api/enviar_pedido: {e}")
        return jsonify({"mensaje": "error_servidor", "detalle": str(e)}), 500






@app.route('/api/congelar_pedido', methods=['POST'])
@login_required
@user_required
def congelar_pedido():
    if 'username' not in session: return jsonify({"mensaje":"No has iniciado sesión"}),403
    data=request.get_json(); pedido_id=data.get('id'); username=session['username']
    if not pedido_id: return jsonify({"mensaje":"ID no válido"}),400
    with get_db_connection() as conn:
        conn.execute("UPDATE pedidos SET estado='Congelado' WHERE id=? AND username=?", (pedido_id, username))
        conn.commit()
    return jsonify({"mensaje":f"Pedido {pedido_id} congelado"})



# ------------------- MISION -------------------
@app.route('/mision')
@login_required
@user_required
def mision():
    if 'username' not in session: return redirect(url_for("login1"))
    username = session['username']
    saldo = get_saldo(username)  # recalcular saldo actualizado

    with get_db_connection() as conn:
        row = conn.execute("SELECT vip_nivel FROM users WHERE username=?", (username,)).fetchone()
        vip_nivel = row['vip_nivel'] if row else 1
        costo_vip = 50 + (vip_nivel - 1) * 20 if vip_nivel < 5 else 0

        filtro = request.args.get("filtro", "todos")
        query = "SELECT * FROM pedidos WHERE username=?"
        if filtro == "incompleto": query += " AND estado = 'Pendiente'"
        pedidos = conn.execute(query + " ORDER BY id DESC", (username,)).fetchall()

        total_pedidos = conn.execute("SELECT COUNT(*) FROM pedidos WHERE username=?", (username,)).fetchone()[0]
        completados = conn.execute("SELECT COUNT(*) FROM pedidos WHERE username=? AND estado='Completado'", (username,)).fetchone()[0]
        incompletos = total_pedidos - completados

    progreso = (completados / total_pedidos) * 100 if total_pedidos > 0 else 0
    return render_template("mision.html", saldo=saldo, vip_nivel=vip_nivel, costo_vip=costo_vip,
                           pedidos=pedidos, completados=completados, incompletos=incompletos,
                           total_pedidos=total_pedidos, progreso=progreso, filtro=filtro)





# ---------------- RECARGAS ----------------
@app.route('/recarga')
@login_required
@user_required
def recarga():
    return render_template('recarga.html')



from werkzeug.utils import secure_filename

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'comprobantes')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/guardar_recarga", methods=["POST"])
@login_required
@user_required
def guardar_recarga():
    if 'username' not in session:
        return redirect(url_for('login1'))

    username = session['username']
    monto = request.form.get("monto")
    metodo_pago = request.form.get("metodo_pago")
    file = request.files.get("comprobante")

    filename_db = None
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        filename_db = f"comprobantes/{filename}"

    # Inserción sin sumar aún al saldo
    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO recargas (username, monto, metodo_pago, imagen, estado) 
            VALUES (?, ?, ?, ?, 'Pendiente')
        """, (username, monto, metodo_pago, filename_db))
        conn.commit()

    flash("Recarga enviada para revisión del administrador.", "info")
    return redirect(url_for("recarga2"))








@app.route('/recarga2')
@login_required
@user_required
def recarga2():
    if 'username' not in session: 
        return redirect(url_for('login1'))

    username = session['username']
    with get_db_connection() as conn:
        recarga = conn.execute("SELECT * FROM recargas WHERE username=? ORDER BY id DESC LIMIT 1", (username,)).fetchone()
        tarjeta = conn.execute("SELECT * FROM tarjetas WHERE username=? ORDER BY id DESC LIMIT 1", (username,)).fetchone()

    if not recarga: 
        flash("No se encontró recarga", "error")
        return redirect(url_for("recarga"))

    # ✅ Si no tiene tarjeta registrada, redirigir a tarjeta.html
    if not tarjeta:
        flash("Debes registrar una tarjeta antes de continuar", "info")
        return redirect(url_for("tarjeta"))

    return render_template('recarga2.html', recarga=recarga, tarjeta=tarjeta)


@app.route('/procesar_recarga', methods=['POST'])
@login_required
@user_required
def procesar_recarga():
    if "username" not in session:
        return redirect(url_for("login1"))

    numero_serie = request.form.get('numero_serie')
    monto = float(request.form.get('monto', 0))
    metodo_pago = request.form.get('metodo_pago')
    nombre = request.form.get('username')
    numero_cuenta = request.form.get('numero_cuenta')
    cci = request.form.get('cci')
    nombre_titular = request.form.get('nombre_titular')

    archivo = request.files.get('captura_pago')
    nombre_archivo = None
    if archivo:
        filename = secure_filename(archivo.filename)
        nombre_archivo = os.path.join(UPLOAD_FOLDER, filename)
        archivo.save(nombre_archivo)

    fecha_actual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO pagos (numero_serie, monto, metodo_pago, nombre, numero_cuenta, cci, nombre_titular, captura_pago, fecha)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (numero_serie, monto, metodo_pago, nombre, numero_cuenta, cci, nombre_titular, nombre_archivo, fecha_actual))
    conn.commit()
    conn.close()

    return """<script>alert('✅ Pago enviado correctamente'); window.location.href='/inicio';</script>"""




# ---------------- PERFIL ----------------
@app.route('/yo')
@login_required
@user_required
def yo():
    if 'username' not in session: 
        return redirect(url_for('login1'))

    username = session['username']
    user = get_user(username=username)

    if not user: 
        flash("Usuario no encontrado", "error")
        return redirect(url_for('inicio'))

    saldo = get_saldo(username)  # 👈 traemos el saldo

    return render_template(
        'yo.html',
        phone=user['phone'],
        vip_nivel=user['vip_nivel'],
        saldo=saldo   # 👈 lo mandamos al template
    )


@app.route('/modificar_password', methods=['GET','POST'])
@login_required
@user_required
def modificar_password():
    if 'user_id' not in session: return redirect(url_for('login1'))
    user_id=session['user_id']
    if request.method=='POST':
        actual=request.form.get('password_actual',''); nueva=request.form.get('nueva_contrasena',''); confirmar=request.form.get('confirmar_contrasena','')
        if not actual or not nueva or not confirmar: flash("Completa todos los campos","error"); return redirect(url_for('modificar_password'))
        if nueva!=confirmar: flash("Contraseñas nuevas no coinciden","error"); return redirect(url_for('modificar_password'))
        user=get_user(user_id=user_id)
        if not user or not check_password_hash(user['password'], actual): flash("Contraseña actual incorrecta","error"); return redirect(url_for('modificar_password'))
        with get_db_connection() as conn:
            conn.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(nueva), user_id))
            conn.commit()
        flash("Contraseña actualizada con éxito","success"); return redirect(url_for('yo'))
    return render_template('modificar_password.html')


# ---------------- RETIROS ----------------
@app.route("/retiro")
@login_required
@user_required
def retiro():
    if 'username' not in session: return redirect(url_for("login1"))
    saldo=get_saldo(session["username"])
    with get_db_connection() as conn:
        user=conn.execute("SELECT username, phone FROM users WHERE username=?", (session["username"],)).fetchone()
    if not user: return "Usuario no encontrado", 404
    return render_template("retiro.html", username=user["username"], phone=user["phone"], saldo=saldo)

@app.route("/procesar_retiro", methods=["POST"])
@login_required
@user_required
def procesar_retiro():
    if 'username' not in session:
        return "no_login", 403

    username = session['username']
    monto = float(request.form.get("monto", 0))
    contrasena_fondo = request.form.get("contrasena_fondo", "").strip()

    if monto <= 0:
        return "monto_invalido", 400

    with get_db_connection() as conn:
        # Obtener saldo actual y contraseña del fondo
        user_saldo = conn.execute("SELECT saldo FROM usuarios_saldo WHERE user_id = (SELECT id FROM users WHERE username=?)", (username,)).fetchone()
        user_fondo = conn.execute("SELECT contrasena_fondo FROM tarjetas WHERE username=?", (username,)).fetchone()

        if not user_saldo or user_saldo['saldo'] < monto:
            return "saldo_insuficiente", 400

        if not user_fondo or user_fondo['contrasena_fondo'] != contrasena_fondo:
            return "password_incorrecta", 400

        # Guardar retiro como Pendiente
        conn.execute("""
            INSERT INTO retiros (username, monto, fecha, estado) 
            VALUES (?, ?, ?, 'Pendiente')
        """, (username, monto, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()

    return "ok", 200







@app.route('/informe')
@login_required
@user_required
def informe():
    return render_template('informe.html')

@app.route('/historial_recarga')
@login_required
@user_required
def historial_recarga():
    if 'username' not in session:
        flash("Debes iniciar sesión para ver tu historial", "error")
        return redirect(url_for('login1'))

    username = session['username']  # Usamos el nombre de usuario
    conn = get_db_connection()
    c = conn.cursor()

    # Obtener recargas de este usuario
    c.execute("""
        SELECT id, monto, metodo_pago, fecha
        FROM recargas
        WHERE username = ?
        ORDER BY id DESC
    """, (username,))
    recargas = c.fetchall()

    # Calcular total acumulado
    total = sum(r['monto'] for r in recargas)

    conn.close()

    return render_template('historial_recarga.html', recargas=recargas, total=total)



@app.route('/historial_retiro')
@login_required
@user_required
def historial_retiro():
    if 'username' not in session:
        flash("Debes iniciar sesión para ver tu historial de retiros", "error")
        return redirect(url_for('login1'))

    username = session['username']
    conn = get_db_connection()
    c = conn.cursor()

    # Obtener retiros del usuario actual
    c.execute("""
        SELECT id, monto, fecha
        FROM retiros
        WHERE username = ?
        ORDER BY id DESC
    """, (username,))
    retiros = c.fetchall()

    # Calcular total retirado
    total = sum(r['monto'] for r in retiros)

    conn.close()

    return render_template('historial_retiro.html', retiros=retiros, total=total)


@app.route('/detalles')
@login_required
@user_required
def detalles():
    return render_template('detalles.html')

@app.route('/idioma')
@login_required
@user_required
def idioma():
    return render_template('idioma.html')

@app.route('/mensajes')
@login_required
@user_required
def mensajes():
    return render_template('mensajes.html')

# ---------------- TARJETAS ----------------
@app.route("/tarjeta")
@login_required
@user_required
def tarjeta():
    if 'username' not in session: return redirect(url_for("login1"))
    return render_template("tarjeta.html")

@app.route("/guardar_tarjeta", methods=["POST"])
@login_required
@user_required
def guardar_tarjeta():
    if 'username' not in session: return redirect(url_for("login1"))
    username=session['username']
    banco=request.form["banco"]; numero_cuenta=request.form["numero_cuenta"]
    cci=request.form["cci"]; nombre_titular=request.form["nombre_titular"]
    contrasena_fondo=request.form["contrasena_fondo"]
    with get_db_connection() as conn:
        conn.execute("""INSERT INTO tarjetas (username,banco,numero_cuenta,cci,nombre_titular,contrasena_fondo)
                        VALUES (?,?,?,?,?,?)""", (username,banco,numero_cuenta,cci,nombre_titular,contrasena_fondo))
        conn.commit()
    flash("✅ Tarjeta guardada con éxito","success")
    return redirect(url_for("inicio"))

    
# ------------------- MEJORAR VIP -------------------
@app.route('/mejorar_vip', methods=['POST'])
@login_required
@user_required
def mejorar_vip():
    if 'username' not in session:
        return redirect(url_for("login1"))
    username = session['username']

    with get_db_connection() as conn:
        user = conn.execute("SELECT vip_nivel, id FROM users WHERE username=?", (username,)).fetchone()
        vip_nivel = user['vip_nivel'] if user else 1
        costo = 50 + (vip_nivel - 1) * 20

        saldo_actual = get_saldo(username)
        if saldo_actual < costo:
            flash("Saldo insuficiente para mejorar VIP", "error")
            return redirect(url_for("mision"))
        if vip_nivel >= 5:
            flash("Ya tienes VIP máximo", "info")
            return redirect(url_for("mision"))

        # ✅ Descontar saldo real
        conn.execute("""
            UPDATE usuarios_saldo 
            SET saldo = saldo - ? 
            WHERE user_id=?
        """, (costo, user['id']))

        # Subir VIP
        conn.execute("UPDATE users SET vip_nivel = vip_nivel + 1 WHERE id=?", (user['id'],))

        # Registrar gasto en retiros
        conn.execute("""
            INSERT INTO retiros (username, monto, fecha, estado) 
            VALUES (?, ?, ?, 'Completado')
        """, (username, costo, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

        # Asignar nuevos pedidos
        asignar_pedidos_desde_base(conn, username, vip_nivel + 1)

        conn.commit()

    flash(f"Felicidades, ahora eres VIP{vip_nivel+1}!", "success")
    return redirect(url_for("mision"))






# ---------------- PEDIDOS ----------------
@app.route('/admin')
@admin_required
def admin():
    with get_db_connection() as conn:
        # Recargas pendientes
        recargas_pendientes = conn.execute(
            "SELECT * FROM recargas WHERE estado='Pendiente'"
        ).fetchall()

        # Retiros pendientes
        retiros_pendientes = conn.execute(
            "SELECT * FROM retiros WHERE estado='Pendiente'"
        ).fetchall()

        # Últimos intentos de login
        logueos_intentos = conn.execute(
            "SELECT * FROM login_attempts ORDER BY last_attempt DESC LIMIT 50"
        ).fetchall()

        # Conexión activa
        one_min_ago = datetime.now() - timedelta(seconds=PING_TIMEOUT)

        # Admins conectados
        admins_conectados = conn.execute(
            "SELECT COUNT(*) as total FROM users WHERE is_admin IN ('1','98C12345P') AND last_ping > ?",
            (one_min_ago,)
        ).fetchone()['total']

        # Usuarios normales conectados
        usuarios_conectados = conn.execute(
            "SELECT COUNT(*) as total FROM users WHERE is_admin='0' AND last_ping > ?",
            (one_min_ago,)
        ).fetchone()['total']

        # Invitaciones
        invitaciones_rows = conn.execute("SELECT * FROM invitations").fetchall()

        # Pedidos con fecha_limite NULL
        pedidos_rows = conn.execute(
            "SELECT * FROM pedidos WHERE username IS NULL ORDER BY id DESC"
        ).fetchall()


        # Convertir a diccionarios
        recargas = [dict(r) for r in recargas_pendientes]
        retiros = [dict(r) for r in retiros_pendientes]
        intentos = [dict(i) for i in logueos_intentos]
        invitaciones = [dict(i) for i in invitaciones_rows]
        pedidos = [dict(p) for p in pedidos_rows]

        return render_template(
            'admin.html',
            recargas=recargas,
            retiros=retiros,
            intentos=intentos,
            invitaciones=invitaciones,
            pedidos=pedidos,
            admins_conectados=admins_conectados,
            usuarios_conectados=usuarios_conectados,
            ping_interval=PING_INTERVAL,
            datetime=datetime   # <-- PASAMOS datetime AL TEMPLATE
        )





@app.route('/admin/recargas')
@admin_required
def admin_recargas_api():
    with get_db_connection() as conn:
        recargas = conn.execute(
            "SELECT id, username, monto, estado FROM recargas ORDER BY id DESC LIMIT 50"
        ).fetchall()
    recargas_list = [dict(r) for r in recargas]
    return jsonify(recargas_list)

@app.route('/admin/retiros')
@admin_required
def admin_retiros_api():
    with get_db_connection() as conn:
        retiros = conn.execute(
            "SELECT id, username, monto, estado FROM retiros ORDER BY id DESC LIMIT 50"
        ).fetchall()
    retiros_list = [dict(r) for r in retiros]
    return jsonify(retiros_list)

@app.route('/admin/intentos')
@admin_required
def admin_intentos():
    if 'username' not in session or str(session.get('is_admin')) not in ["1", "98C12345P"]:
        return jsonify({"error": "No autorizado"}), 403

    with get_db_connection() as conn:
        intentos = conn.execute(
            "SELECT * FROM login_attempts ORDER BY last_attempt DESC LIMIT 50"
        ).fetchall()

    intentos_list = [dict(i) for i in intentos]
    return jsonify(intentos_list)

@app.route('/admin/intrusos')
@admin_required
def admin_intrusos():
    if 'username' not in session or str(session.get('is_admin')) not in ["1", "98C12345P"]:
        return jsonify({"error": "No autorizado"}), 403

    with get_db_connection() as conn:
        intrusos = conn.execute("""
            SELECT phone, attempts, last_attempt, ip, attempt_hour,
            CASE 
                WHEN attempts >= 5 THEN 'Alto'
                WHEN attempts >= 3 THEN 'Medio'
                ELSE 'Bajo'
            END AS nivel_riesgo
            FROM login_attempts
            ORDER BY last_attempt DESC
            LIMIT 50
        """).fetchall()

    return render_template("admin.html", intrusos=[dict(i) for i in intrusos])

# ✅ Actualizar código de invitación
@app.route('/update_invitation/<int:inv_id>', methods=['POST'])
@admin_required
def update_invitation(inv_id):
    new_code = request.form.get('code')
    if not new_code:
        flash("El código no puede estar vacío", "error")
        return redirect(url_for('admin'))

    with get_db_connection() as conn:
        conn.execute(
            "UPDATE invitations SET code = ? WHERE id = ?",
            (new_code, inv_id)
        )
        conn.commit()

    flash("Invitación actualizada correctamente", "success")
    return redirect(url_for('admin'))




@app.route('/admin/aprobar_recarga/<int:recarga_id>', methods=['POST'])
@admin_required
def aprobar_recarga(recarga_id):
    with get_db_connection() as conn:
        recarga = conn.execute("SELECT * FROM recargas WHERE id=?", (recarga_id,)).fetchone()
        if recarga:
            user = conn.execute("SELECT id FROM users WHERE username=?", (recarga['username'],)).fetchone()
            if user:
                conn.execute("UPDATE usuarios_saldo SET saldo = saldo + ? WHERE user_id=?", (recarga['monto'], user['id']))
                conn.execute("UPDATE recargas SET estado='Completado' WHERE id=?", (recarga_id,))
                conn.commit()
    return redirect(url_for('admin'))

@app.route('/admin/rechazar_recarga/<int:recarga_id>', methods=['POST'])
@admin_required
def rechazar_recarga(recarga_id):
    with get_db_connection() as conn:
        conn.execute("UPDATE recargas SET estado='Rechazado' WHERE id=?", (recarga_id,))
        conn.commit()
    return redirect(url_for('admin'))

@app.route('/admin/aprobar_retiro/<int:retiro_id>', methods=['POST'])
@admin_required
def aprobar_retiro(retiro_id):
    with get_db_connection() as conn:
        retiro = conn.execute("SELECT * FROM retiros WHERE id=?", (retiro_id,)).fetchone()
        if retiro:
            user = conn.execute("SELECT id FROM users WHERE username=?", (retiro['username'],)).fetchone()
            if user:
                conn.execute("UPDATE usuarios_saldo SET saldo = saldo - ? WHERE user_id=?", (retiro['monto'], user['id']))
                conn.execute("UPDATE retiros SET estado='Completado' WHERE id=?", (retiro_id,))
                conn.commit()
    return redirect(url_for('admin'))

@app.route('/admin/rechazar_retiro/<int:retiro_id>', methods=['POST'])
@admin_required
def rechazar_retiro(retiro_id):
    with get_db_connection() as conn:
        conn.execute("UPDATE retiros SET estado='Rechazado' WHERE id=?", (retiro_id,))
        conn.commit()
    return redirect(url_for('admin'))


@app.route('/admin/pedidos_null', methods=['GET', 'POST'])
@admin_required
def pedidos_null():
    from datetime import datetime, timedelta
    from flask import request, jsonify, render_template

    with get_db_connection() as conn:
        if request.method == 'POST':
            horas_agregar = int(request.form.get('horas_limite', 24))
            for key, value in request.form.items():
                if key.startswith('username_'):
                    pedido_id = key.split('_')[1]
                    username = request.form.get(f'username_{pedido_id}') or None
                    nombre = request.form.get(f'nombre_{pedido_id}') or None
                    monto = request.form.get(f'monto_{pedido_id}') or 0
                    total = request.form.get(f'total_{pedido_id}') or 0
                    comision = request.form.get(f'comision_{pedido_id}') or 0
                    estado = request.form.get(f'estado_{pedido_id}') or 'Pendiente'
                    vip_nivel = request.form.get(f'vip_nivel_{pedido_id}') or 0
                    descripcion = request.form.get(f'descripcion_{pedido_id}') or None

                    fecha_limite = datetime.now() + timedelta(hours=horas_agregar)

                    conn.execute("""
                        UPDATE pedidos SET
                            username=?, nombre=?, monto=?, total=?, comision=?, estado=?, fecha_limite=?, vip_nivel=?, descripcion=?
                        WHERE id=?
                    """, (username, nombre, monto, total, comision, estado, fecha_limite, vip_nivel, descripcion, pedido_id))
            conn.commit()

            # Pedidos actualizados
            pedidos_rows = conn.execute("""
                SELECT * FROM pedidos WHERE username IS NULL OR TRIM(username) = '' ORDER BY id DESC
            """).fetchall()
            pedidos = [dict(p) for p in pedidos_rows]

            # Generar tbody dinámico
            tbody_html = ""
            for p in pedidos:
                tbody_html += f"""
                <tr>
                    <td>{p['id']}</td>
                    <td><input type='text' name='username_{p["id"]}' value='{p["username"] or ""}'></td>
                    <td><input type='text' name='nombre_{p["id"]}' value='{p["nombre"] or ""}'></td>
                    <td><input type='number' step='any' name='monto_{p["id"]}' value='{p["monto"] or 0}'></td>
                    <td><input type='number' step='any' name='total_{p["id"]}' value='{p["total"] or 0}'></td>
                    <td><input type='number' step='any' name='comision_{p["id"]}' value='{p["comision"] or 0}'></td>
                    <td>
                        <select name='estado_{p["id"]}'>
                            <option value='Pendiente' {"selected" if p["estado"]=="Pendiente" else ""}>Pendiente</option>
                            <option value='Completado' {"selected" if p["estado"]=="Completado" else ""}>Completado</option>
                            <option value='Congelado' {"selected" if p["estado"]=="Congelado" else ""}>Congelado</option>
                        </select>
                    </td>
                    <td><input type='datetime-local' name='fecha_limite_{p["id"]}' value='{p["fecha_limite"].replace(" ", "T") if p["fecha_limite"] else ""}'></td>
                    <td><input type='number' name='vip_nivel_{p["id"]}' value='{p["vip_nivel"] or 0}'></td>
                    <td><input type='text' name='descripcion_{p["id"]}' value='{p["descripcion"] or ""}'></td>
                </tr>
                """

            return jsonify({"success": True, "message": f"✅ Pedidos actualizados (+{horas_agregar}h)", "html": tbody_html})

        # GET normal
        pedidos_rows = conn.execute("""
            SELECT * FROM pedidos WHERE username IS NULL OR TRIM(username) = '' ORDER BY id DESC
        """).fetchall()
        pedidos = [dict(p) for p in pedidos_rows]

    return render_template('admin.html', pedidos=pedidos)


@app.route('/admin/totales')
@admin_required
def totales():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute('SELECT SUM(monto) FROM recargas WHERE estado="Completado"')
    recargas_total = cur.fetchone()[0] or 0

    cur.execute('SELECT SUM(monto) FROM retiros WHERE estado="Completado"')
    retiros_total = cur.fetchone()[0] or 0

    conn.close()

    return jsonify({
        'recargas': recargas_total,
        'retiros': retiros_total,
        'neto': recargas_total - retiros_total
    })



    
@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        with get_db_connection() as conn:
            conn.execute("UPDATE users SET is_online=0 WHERE id=?", (user_id,))
            conn.commit()

    session.clear()
    flash("Has cerrado sesión", "info")
    return redirect(url_for('login1'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))  # Render usará PORT, local usas 8080
    app.run(host="0.0.0.0", port=port)

