# Analizador-log-ssh
## 📌 Descripción
Este proyecto es un **mini sistema de detección de intrusos (IDS)** escrito en **python** para **sistemas operativos basados en debian linux**. El programa analiza registros de autenticación de SSH usando `journalctl` y detecta:

- Intentos fallidos de inicio de sesión (`Failed password`)  
- Direcciones IP responsables de múltiples fallos  
- Genera un **reporte en texto** con las IPs sospechosas  

Es una herramienta educativa inspirada en **Fail2Ban**, diseñada para aprender:  
- Manejo de logs en **Parrot/Linux**  
- Automatización con **Python**  
- Conceptos de **ciberseguridad ofensiva y defensiva**

---

## 🚀 Uso
1. Clonar el repositorio:
   ```bash
   git clone https://github.com/BernardoUG/Analizador-log-ssh.git
   cd Analizador-log-ssh
