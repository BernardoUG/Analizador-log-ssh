import subprocess
import csv

# Número máximo de IPs/usuarios a mostrar en los tops
TOP_N = 10


def extraer_usuario_e_ip(linea: str):
    partes = linea.split()
    usuario = None
    ip = None

    # IP: a partir de la palabra "from"
    if "from" in partes:
        idx_from = partes.index("from") + 1
        if idx_from < len(partes):
            ip = partes[idx_from]
            
    try:
        idx_failed = partes.index("Failed")
    except ValueError:
        return usuario, ip

    if (
        idx_failed + 5 < len(partes)
        and partes[idx_failed + 3] == "invalid"
        and partes[idx_failed + 4] == "user"
    ):
        usuario = partes[idx_failed + 5]
    elif idx_failed + 3 < len(partes):
        usuario = partes[idx_failed + 3]

    return usuario, ip


def procesar_logs(login: str):
    ip_info = {}
    contador_fallos = 0

    for linea in login.splitlines():
        if "failed password" in linea.lower():
            contador_fallos += 1

            usuario, ip = extraer_usuario_e_ip(linea)

            if ip is None:
                # Si no se pudo extraer IP, no suma en las estadísticas por IP
                continue

            data_ip = ip_info.setdefault(ip, {"total": 0, "usuarios": {}})
            data_ip["total"] += 1

            if usuario:
                data_ip["usuarios"][usuario] = data_ip["usuarios"].get(usuario, 0) + 1

    return ip_info, contador_fallos


def calcular_top_ips(ataques_ordenados, top_n=TOP_N):
    return ataques_ordenados[:top_n]


def calcular_top_usuarios(ip_info, top_n=TOP_N):
    usuarios_objetivo = {}

    for _, data in ip_info.items():
        for usuario, conta in data["usuarios"].items():
            usuarios_objetivo[usuario] = usuarios_objetivo.get(usuario, 0) + conta

    top_usuarios = sorted(
        usuarios_objetivo.items(),
        key=lambda x: x[1],
        reverse=True
    )

    return top_usuarios[:top_n]


def clasificar_ataque(data_ip):
    #Clasifica el tipo de ataque de una IP:
    total = data_ip.get("total", 0)
    usuarios_dict = data_ip.get("usuarios", {})

    if total == 0 or not usuarios_dict:
        return "sin_clasificacion_clara", "Sin datos suficientes de usuario."

    #Usuario más atacado
    usuarios_ordenados = sorted(
        usuarios_dict.items(),
        key=lambda x: x[1],
        reverse=True
    )

    usuario_principal, intentos_principales = usuarios_ordenados[0]
    ratio_principal = intentos_principales / total
    num_usuarios = len(usuarios_dict)

    # Regla fuerza bruta:
    #   - total_intentos >= 20
    #   - usuario principal tiene >= 70% de los intentos
    if total >= 20 and ratio_principal >= 0.70:
        detalle = (
            f"Fuerza bruta contra '{usuario_principal}' "
            f"({intentos_principales}/{total} intentos, "
            f"{ratio_principal*100:.1f}% del total)."
        )
        return "fuerza_bruta", detalle

    # Regla enumeración de usuarios:
    #   - número_de_usuarios_distintos >= 10
    #   - ningún usuario tiene más del 30% de los intentos
    ratios = [c / total for c in usuarios_dict.values()]
    if num_usuarios >= 10 and all(r <= 0.30 for r in ratios):
        detalle = (
            f"Enumeración de usuarios: {num_usuarios} usuarios distintos, "
            f"{total} intentos totales."
        )
        return "enumeracion_usuarios", detalle

    detalle_usuarios = ", ".join(
        f"{u}={c}" for u, c in usuarios_ordenados[:3]
    )
    detalle = (
        f"Patrón mixto: total {total} intentos. "
        f"Usuarios más atacados: {detalle_usuarios}..."
    )
    return "mixto", detalle


def generar_reportes(ataques_ordenados, ip_info, top_usuarios, ruta_txt="report.txt", ruta_csv="report.csv"):
    #Genera los reportes:
    with open(ruta_txt, "w") as r:
        r.write("==== REPORTE DE INTENTOS FALLIDOS SSH ====\n\n")

        if not ataques_ordenados:
            r.write("No se encontraron IPs con más de un intento fallido.\n")
        else:
            r.write(
                "=== IPs con más de un intento fallido "
                "(ordenadas por número de ataques) ===\n"
            )
            for ip, data in ataques_ordenados:
                r.write(f"\nIP: {ip} --> {data['total']} intentos\n")
                usuarios_ordenados = sorted(
                    data["usuarios"].items(),
                    key=lambda x: x[1],
                    reverse=True
                )
                for usuario, conta in usuarios_ordenados:
                    r.write(f"   Usuario '{usuario}': {conta} intentos\n")

                #Clasificación del ataque
                tipo_ataque, detalle = clasificar_ataque(data)
                r.write(f"   Tipo de ataque: {tipo_ataque}\n")
                r.write(f"   Detalle: {detalle}\n")

        #Sección Top N IPs
        r.write("\n\n=== Top IPs más agresivas ===\n")
        top_ips = calcular_top_ips(ataques_ordenados, TOP_N)
        if not top_ips:
            r.write("No hay IPs suficientes para el top.\n")
        else:
            for idx, (ip, data) in enumerate(top_ips, start=1):
                r.write(f"{idx}) {ip} -> {data['total']} intentos\n")

        #Top usuarios más atacados
        r.write("\n\n=== Usuarios más atacados ===\n")
        if not top_usuarios:
            r.write("No hay usuarios suficientes para el top.\n")
        else:
            for idx, (usuario, total_u) in enumerate(top_usuarios, start=1):
                r.write(f"{idx}) {usuario} -> {total_u} intentos\n")

    # Generamos CSV
    with open(ruta_csv, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["ip", "intentos_totales", "usuario", "intentos_usuario", "tipo_ataque"])

        for ip, data in ataques_ordenados:
            tipo_ataque, _ = clasificar_ataque(data)

            usuarios_ordenados = sorted(
                data["usuarios"].items(),
                key=lambda x: x[1],
                reverse=True
            )

            # Si no hay usuarios, igual registramos la IP
            if not usuarios_ordenados:
                writer.writerow([ip, data["total"], "", "", tipo_ataque])
            else:
                for usuario, conta in usuarios_ordenados:
                    writer.writerow([ip, data["total"], usuario, conta, tipo_ataque])


def main():
    try:
        # Comando con journalctl
        login = subprocess.check_output(
            ["journalctl", "-u", "ssh", "-n", "200"],
            text=True
        )
        print("=== Vista rápida del log (primeros 200 caracteres) ===")
        print(login[0:200])

    except subprocess.CalledProcessError as error:
        print(f"Command failed with return code {error.returncode}")

    else:
        # Procesar logs y construir estructura ip_info
        ip_info, contador_fallos = procesar_logs(login)

        print("\n========================================")
        print("=== Resumen de actividad sospechosa ===")
        print("========================================")
        print(f"Total de intentos fallidos encontrados: {contador_fallos}")

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
                usuarios_ordenados = sorted(
                    data["usuarios"].items(),
                    key=lambda x: x[1],
                    reverse=True
                )
                for usuario, conta in usuarios_ordenados:
                    print(f"   Usuario '{usuario}': {conta} intentos")

                # Clasificación del ataque
                tipo_ataque, detalle = clasificar_ataque(data)
                print(f"   Tipo de ataque: {tipo_ataque}")
                print(f"   Detalle: {detalle}")

            # Top N IPs más agresivas
            print("\n=== Top IPs más agresivas ===")
            top_ips = calcular_top_ips(ataques_ordenados, TOP_N)
            if not top_ips:
                print("No hay IPs suficientes para el top.")
            else:
                for idx, (ip, data) in enumerate(top_ips, start=1):
                    print(f"{idx}) {ip} -> {data['total']} intentos")

            # Top usuarios más atacados
            print("\n=== Usuarios más atacados ===")
            top_usuarios = calcular_top_usuarios(ip_info, TOP_N)
            if not top_usuarios:
                print("No hay usuarios suficientes para el top.")
            else:
                for idx, (usuario, total_u) in enumerate(top_usuarios, start=1):
                    print(f"{idx}) {usuario} -> {total_u} intentos")

            # Generar reporte en TXT y CSV
            generar_reportes(ataques_ordenados, ip_info, top_usuarios)

    finally:
        print("\n==== Programa terminado ====")


if __name__ == "__main__":
    main()
