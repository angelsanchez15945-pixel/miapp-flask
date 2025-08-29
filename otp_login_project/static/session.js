// static/session.js
const TIEMPO_EXPIRACION = 3 * 60 * 1000; // 5 min
let tiempoUltimaActividad = new Date().getTime();

function actualizarActividad() {
    tiempoUltimaActividad = new Date().getTime();
}

document.addEventListener('mousemove', actualizarActividad);
document.addEventListener('keydown', actualizarActividad);
document.addEventListener('click', actualizarActividad);

setInterval(() => {
    if (new Date().getTime() - tiempoUltimaActividad > TIEMPO_EXPIRACION) {
        alert("Tu sesión ha expirado por inactividad.");
        window.location.href = "/logout";
    }
}, 1000);
