import subprocess
import csv

def extraer_usuario_e_ip(linea: str):
    # Extrae el usuario y la IP de una línea de journalctl de sshd.
    partes = linea.split()
    usuario = None
    ip = None

    # IP: a partir de "from"
    if "from" in partes:
        idx_from = partes.index("from") + 1
        if idx_from < len(partes):
            ip = partes[idx_from]

    # Usuario: a partir de "Failed password for ..."
    try:
        idx_failed = partes.index("Failed")
    except ValueError:
        # Si por algún motivo no está "Failed", salimos
        return usuario, ip

    # Patrón 1: "Failed password for invalid user <usuario> from ..."
    # Patrón 2: "Failed password for <usuario> from ..."
    if (
        idx_failed + 5 < len(partes)
        and partes[idx_failed + 3] == "invalid"
        and partes[idx_failed + 4] == "user"
    ):
        usuario = partes[idx_failed + 5]
    elif idx_failed + 3 < len(partes):
        usuario = partes[idx_failed + 3]

    return usuario, ip


def main():
    try:
        # Tu comando original con journalctl (Debian / systemd)
        login = subprocess.check_output(
            ["journalctl", "-u", "ssh", "-n", "200"],
            text=True
        )
        print(login[0:200])  # Vista rápida de los primeros 200 caracteres

    except subprocess.CalledProcessError as error:
        print(f"Command failed with return code {error.returncode}")

    else:
        # Diccionario: ip -> {"total": int, "usuarios": {usuario: int}}
        ip_info = {}
        contador_fallos = 0

        for linea in login.splitlines():
            if "failed password" in linea.lower():
                contador_fallos += 1

                usuario, ip = extraer_usuario_e_ip(linea)

                if ip is None:
                    continue  # si no se pudo extraer IP, no nos sirve para el conteo

                # Diccionario: ip
                data_ip = ip_info.setdefault(ip, {"total": 0, "usuarios": {}})
                data_ip["total"] += 1

                if usuario:
                    data_ip["usuarios"][usuario] = data_ip["usuarios"].get(usuario, 0) + 1

        print(f"\nTotal de intentos fallidos encontrados: {contador_fallos}")

        # Filtrar solo IPs con >1 intentos y ordenarlas por número de ataques
        ataques_ordenados = sorted(
            (
                (ip, data)
                for ip, data in ip_info.items()
                if data["total"] > 1
            ),
            key=lambda x: x[1]["total"],
            reverse=True
        )

        if not ataques_ordenados:
            print("No se encontraron IPs con más de un intento fallido.")
        else:
            print(
                "\n=== IPs con más de un intento fallido "
                "(ordenadas por número de ataques) ==="
            )
            for ip, data in ataques_ordenados:
                print(f"\nIP: {ip} --> {data['total']} intentos")
                # Mostrar también usuarios a los que intentaron acceder
                usuarios_ordenados = sorted(
                    data["usuarios"].items(),
                    key=lambda x: x[1],
                    reverse=True
                )
                for usuario, conta in usuarios_ordenados:
                    print(f"   Usuario '{usuario}': {conta} intentos")

            # Guardar reporte en archivo TXT
            with open("report.txt", "w") as r:
                for ip, data in ataques_ordenados:
                    r.write(f"IP: {ip} - {data['total']} intentos fallidos\n")
                    usuarios_ordenados = sorted(
                        data["usuarios"].items(),
                        key=lambda x: x[1],
                        reverse=True
                    )
                    for usuario, conta in usuarios_ordenados:
                        r.write(f"   Usuario '{usuario}': {conta} intentos\n")
                    r.write("\n")

            # Generar archivo CSV
            with open("report.csv", "w", newline="") as csvfile:
                writer = csv.writer(csvfile)

                writer.writerow(["ip", "intentos_totales", "usuario", "intentos_usuario"])

                for ip, data in ataques_ordenados:
                    usuarios_ordenados = sorted(
                        data["usuarios"].items(),
                        key=lambda x: x[1],
                        reverse=True
                    )

                    # Si no hay usuarios, igual registramos la IP
                    if not usuarios_ordenados:
                        writer.writerow([ip, data["total"], "", ""])
                    else:
                        for usuario, conta in usuarios_ordenados:
                            writer.writerow([ip, data["total"], usuario, conta])

    finally:
        print("==== Programa terminado ====")


if __name__ == "__main__":
    main()
