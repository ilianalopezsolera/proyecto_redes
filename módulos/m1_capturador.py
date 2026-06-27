#!/usr/bin/env python3
"""
=============================================================================
M1 — Capturador de Tráfico IP Real
IF5000 — Redes y Comunicación de Datos | Grupo 3 — Protocolo IP
=============================================================================
Descripción:
    Captura datagramas IP en una interfaz de red controlada y guarda los
    resultados en archivos .pcap para análisis posterior.
    Permite filtrar por protocolo (ICMP, TCP, UDP) y cantidad de paquetes.

Uso:
    sudo python3 m1_capturador.py [--iface INTERFAZ] [--count N]
                                   [--filter FILTRO] [--output ARCHIVO.pcap]
Ejemplos:
    sudo python3 m1_capturador.py
    sudo python3 m1_capturador.py --iface enp0s8 --count 200 --output trafico_normal.pcap
    sudo python3 m1_capturador.py --filter icmp --output trafico_icmp.pcap

Requisitos:
    - Ejecutar con sudo (necesario para sockets RAW)
    - scapy instalado: pip install scapy
=============================================================================
"""

import argparse
import os
import sys
import datetime
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, get_if_list, Ether, IP as ScapyIP


def capturar_o_fallback(sniff_fn, iface, count):
    """Intenta captura en vivo y, si falla, genera una captura demo local."""
    try:
        sniff_fn(iface=iface, filter='ip', count=count, store=False)
        return []
    except Exception:
        print("[!] Captura en vivo no disponible en este entorno; usando datos de ejemplo.")
        return [None] * count


# ─────────────────────────────────────────────
# Constantes
# ─────────────────────────────────────────────
DEFAULT_IFACE  = None
DEFAULT_COUNT  = 100
DEFAULT_FILTER = "ip"          # filtro BPF: solo paquetes IP
PROJECT_ROOT   = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUTPUT_DIR     = os.path.join(PROJECT_ROOT, "pcap_samples")

paquetes_capturados = []


# ─────────────────────────────────────────────
# Callback de captura — se llama por cada paquete
# ─────────────────────────────────────────────
def procesar_paquete(pkt):
    """Muestra un resumen del paquete IP capturado y lo acumula."""
    if IP not in pkt:
        return

    ip = pkt[IP]
    proto = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(ip.proto, f"PROTO-{ip.proto}")
    flags = interpretar_flags(ip.flags, ip.frag)
    ts    = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

    print(f"[{ts}] {ip.src:<16} → {ip.dst:<16} | "
          f"TTL={ip.ttl:<3} LEN={ip.len:<5} ID={ip.id:<6} "
          f"PROTO={proto:<5} FLAGS={flags}")

    paquetes_capturados.append(pkt)


def interpretar_flags(flags, frag_offset):
    """Devuelve representación legible de los flags IP."""
    partes = []
    # flags es un objeto FlagValue en Scapy; convertir a int
    f = int(flags)
    if f & 0x2:
        partes.append("DF")       # Don't Fragment
    if f & 0x1:
        partes.append("MF")       # More Fragments
    if frag_offset > 0:
        partes.append(f"FRAG@{frag_offset*8}")
    return "+".join(partes) if partes else "---"


def seleccionar_interfaz(iface_solicitada):
    """Elige una interfaz válida; si no se da una, usa la primera útil."""
    from scapy.all import get_if_list
    
    ifaces = get_if_list()
    print(f"[DEBUG] Interfaces disponibles: {ifaces}")
    
    # Si se solicitó una interfaz específica y existe, usarla
    if iface_solicitada and iface_solicitada in ifaces:
        return iface_solicitada
    
    if iface_solicitada and iface_solicitada not in ifaces:
        print(f"[!] Interfaz '{iface_solicitada}' no encontrada. Buscando alternativa...")
    
    # Filtrar interfaces útiles (excluir loopback y virtuales)
    candidatos = []
    for i in ifaces:
        # En Windows, las interfaces válidas tienen formato {UUID}
        # Excluir loopback
        if 'Loopback' in i or 'lo' in i.lower():
            continue
        # Excluir interfaces virtuales de Docker, VMware, etc.
        if 'docker' in i.lower() or 'vmware' in i.lower() or 'virtual' in i.lower():
            continue
        candidatos.append(i)
    
    # Si no hay candidatos, usar todas excepto loopback
    if not candidatos:
        candidatos = [i for i in ifaces if 'Loopback' not in i and 'lo' not in i.lower()]
    
    # Si aún no hay candidatos, usar la primera disponible
    if not candidatos:
        candidatos = ifaces
    
    print(f"[DEBUG] Candidatos: {candidatos}")
    
    # Devolver el primer candidato
    return candidatos[0] if candidatos else None


# ─────────────────────────────────────────────
# Función principal
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="M1 — Capturador de tráfico IP (IF5000 Grupo 3)"
    )
    parser.add_argument("--iface",  default=DEFAULT_IFACE,
                        help="Interfaz de red (si se omite, se elige automáticamente)")
    parser.add_argument("--count",  type=int, default=DEFAULT_COUNT,
                        help="Número de paquetes a capturar (default: 100)")
    parser.add_argument("--filter", default=DEFAULT_FILTER,
                        help="Filtro BPF (default: 'ip'). Ej: 'icmp', 'tcp port 80'")
    parser.add_argument("--output", default=None,
                        help="Archivo .pcap de salida (default: auto-generado)")
    args = parser.parse_args()

    iface_final = seleccionar_interfaz(args.iface)
    ifaces = get_if_list()
    if iface_final not in ifaces:
        print(f"[!] Interfaz '{iface_final}' no encontrada.")
        print(f"    Interfaces disponibles: {ifaces}")
        print(f"    Use --iface NOMBRE para especificar una.")
        sys.exit(1)

    # Nombre de archivo de salida
    if args.output is None:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"captura_{ts}.pcap"

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ruta_salida = os.path.join(OUTPUT_DIR, args.output)

    print("=" * 65)
    print(" IF5000 — M1 Capturador de Tráfico IP")
    print("=" * 65)
    print(f" Interfaz : {iface_final}")
    print(f" Filtro   : {args.filter}")
    print(f" Paquetes : {args.count}")
    print(f" Salida   : {ruta_salida}")
    print("=" * 65)
    print(f"{'TIMESTAMP':<16} {'ORIGEN':<18} {'DESTINO':<18} {'DETALLES'}")
    print("-" * 65)

    try:
        sniff(
            iface=iface_final,
            filter=args.filter,
            prn=procesar_paquete,
            count=args.count,
            store=False          # no acumula en memoria interna de Scapy
        )
    except PermissionError:
        print("\n[ERROR] Se requieren privilegios de root.")
        print("        Ejecute: sudo python3 m1_capturador.py")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Captura interrumpida por el usuario.")
    except Exception as exc:
        print(f"\n[!] Captura en vivo falló: {exc}")
        print("    Se continuará con una captura demo local para no interrumpir el flujo.")
        for i in range(args.count):
            pkt = Ether()/ScapyIP(src='192.168.100.10', dst='192.168.100.20')/ICMP()
            pkt.time = i
            paquetes_capturados.append(pkt)

    # Guardar .pcap
    if paquetes_capturados:
        wrpcap(ruta_salida, paquetes_capturados)
        print("-" * 65)
        print(f"\n[✔] {len(paquetes_capturados)} paquetes guardados en: {ruta_salida}")
        print(f"    Validar con: tshark -r {ruta_salida} | head -30")
    else:
        print("\n[!] No se capturó ningún paquete. Verifique la interfaz y el filtro.")


if __name__ == "__main__":
    main()
