import subprocess

try:
    login = subprocess.check_output(["journalctl", "-u", "ssh", "-n", "200"], text=True)
    print(login[0:200])

except subprocess.CalledProcessError as error:
    print(f"Command failed with return code {error.returncode}")

else:
    ip_contador_fallos = {}
    linea = login.splitlines()
    contador_fallos = 0

    for i in linea:
        if "failed password" in i.lower():
            contador_fallos += 1
            posicion_palabra = i.split()
            if "from" in posicion_palabra:
                ip_posicion = posicion_palabra.index("from") + 1
                ip = posicion_palabra[ip_posicion]
                ip_contador_fallos[ip] = ip_contador_fallos.get(ip, 0) + 1
        else:
            print(f"Se encontraron #{contador_fallos}")

    print("contador de acceso fallido: ", ip_contador_fallos)

    with open("report.txt", "w") as r:
          for ip, contador in ip_contador_fallos.items():
            r.write(f"{ip} #{contador} intento de fallos\n")

finally:
    print("==== Programa terminado ====")
