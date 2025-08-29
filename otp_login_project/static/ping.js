// ping.js
function enviarPingUsuario() {
    fetch('/user/ping', { method: 'POST' })
        .then(res => res.json())
        .then(data => console.log('Ping usuario:', data.status))
        .catch(err => console.error('Error ping usuario:', err));
}

// Ejecutar cada 1 segundos
enviarPingUsuario();
setInterval(enviarPingUsuario, 1000);
