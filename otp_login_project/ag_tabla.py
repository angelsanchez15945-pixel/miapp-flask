import sqlite3

# Cambia este username al que uses en tu sesión Flask
USERNAME = "tu_usuario"

# Conexión a la base de datos
conn = sqlite3.connect("database_fixed.db")
cursor = conn.cursor()

# Lista de pedidos de prueba
pedidos = [
    (USERNAME, "Producto 1", 100.00, 141.00, 70.50, "Pendiente", ""),
    (USERNAME, "Producto 2", 100.00, 76.00, 38.00, "Congelando", ""),
    (USERNAME, "Producto 3", 100.00, 27.00, 10.80, "Completado", "")
]

# Insertar en la tabla pedidos
cursor.executemany("""
    INSERT INTO pedidos (username, nombre, monto, total, comision, estado, imagen)
    VALUES (?, ?, ?, ?, ?, ?, ?)
""", pedidos)

conn.commit()
conn.close()

print("✅ Pedidos de prueba insertados correctamente.")
