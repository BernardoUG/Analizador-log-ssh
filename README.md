# **Analizador-log-ssh**

## 📌 **Descripción**
Este proyecto es un mini sistema de detección de intrusos (IDS) escrito en Python para sistemas operativos basados en Debian/Parrot/Kali que usan systemd.
El programa analiza los registros de autenticación de SSH usando journalctl y detecta:

   - Intentos fallidos de inicio de sesión (Failed password)
   - Direcciones IP responsables de múltiples fallos
   - Usuarios a los que intentaron acceder (por ejemplo: root, admin, usuarios inválidos)
   - Genera un reporte en texto con las IPs sospechosas ordenadas por número de ataques

Es una herramienta educativa inspirada en Fail2Ban, diseñada para aprender:

   - Manejo de logs en Parrot/Linux
   - Automatización con Python
   - Conceptos básicos de ciberseguridad ofensiva y defensiva

---

## 🧩 **¿Qué hace exactamente el script?**

El script ejecuta:
```
journalctl -u ssh -n 200
```

y luego:

- Busca líneas que contengan Failed password.
- Extrae:
   - La IP de origen (después de la palabra from)
   - El usuario al que intentaron acceder (incluyendo invalid user)
- Cuenta cuántos intentos fallidos tiene cada IP y cada usuario.
- Filtra solo las IPs con más de 1 intento fallido.
- Ordena las IPs por número de ataques (de mayor a menor).
- Muestra la información en pantalla y la guarda en un archivo report.txt, con este formato:
```
IP: 185.32.44.12 - 15 intentos fallidos
   Usuario 'root': 10 intentos
   Usuario 'admin': 5 intentos
```
---
## ⚙️ **Requisitos**

Los requisitos son:
   - Python 3
   - Sistema basado en Debian/Parrot/Kali con systemd
   - Servicio de SSH registrado como ssh en journalctl
   - Permisos para leer los logs del sistema (puede que necesites sudo)
---
## 🚀 **Uso**

1. Clonar el repositorio:
```
git clone https://github.com/BernardoUG/Analizador-log-ssh.git
cd Analizador-log-ssh
```

2. Ejecutar el script en Parrot/Kali/Debian:
```
python3 MainDeteccion.py
```

3. Si tu usuario no tiene permisos para leer los logs de journalctl, puedes usar:
```
sudo python3 MainDeteccion.py
```
---
## 📄 **Salida**

En la terminal verás:
   - Un resumen del log (primeros 200 caracteres)
   - El número total de intentos fallidos detectados
   - La lista de IPs con más de un intento fallido, ordenadas por cantidad
   - Los usuarios a los que intentaron acceder desde cada IP

En el archivo report.txt se guardará un reporte con:
   - IP
   - Número total de intentos fallidos
   - Usuarios atacados desde esa IP y su conteo

Ejemplo de report.txt:
```
IP: 185.32.44.12 - 15 intentos fallidos
   Usuario 'root': 10 intentos
   Usuario 'admin': 5 intentos

IP: 203.0.113.5 - 4 intentos fallidos
   Usuario 'test': 4 intentos
```
---
## 🎯 **Objetivo educativo**
   - Este proyecto está pensado como práctica de:
   - Lectura y parsing de logs con journalctl
   - Uso de subprocess.check_output en Python
   - Manejo de diccionarios y conteo de eventos
   - Primeros pasos hacia la idea de un IDS/IPS tipo Fail2Ban, pero hecho a mano para aprender
