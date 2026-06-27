#!/usr/bin/env python3
"""
=============================================================================
Generador de .pcap de Muestra (sin red real)
IF5000 — Redes y Comunicación de Datos | Grupo 3 — Protocolo IP
=============================================================================
Crea archivos .pcap con paquetes construidos localmente para:
  - Permitir que el docente reproduzca los experimentos SIN necesitar
    las VMs del grupo.
  - Proveer datos de prueba para M2 y M3.

No requiere sudo ni red activa.
Ejecutar: python3 tests/generar_pcap_muestra.py
=============================================================================
"""

import os
import sys
import random

MODULOS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'módulos'))
sys.path.insert(0, MODULOS_DIR)

from scapy.all import (
    IP, TCP, UDP, ICMP, Raw, wrpcap, Ether
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "pcap_samples")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Direcciones del escenario de laboratorio
CLIENT_IP = "192.168.100.10"
SERVER_IP = "192.168.100.20"

# Para paquetes de ejemplo, se usan hosts internos del rango de laboratorio.
# Estas direcciones no afectan el funcionamiento del parser; solo hacen la captura más realista.

paquetes_normales  = []
paquetes_spoofed   = []
paquetes_todos     = []

random.seed(42)   # reproducibilidad

print("[*] Generando paquetes de muestra...")

# ── 1. Tráfico normal (TTL estándar) ──────────────────────
for i in range(60):
    ttl = random.choice([64, 64, 128, 255])   # distribución realista
    proto_pkt = random.choice(["tcp", "udp", "icmp"])

    if proto_pkt == "tcp":
        pkt = (Ether() /
               IP(src=CLIENT_IP if random.random() < 0.5 else SERVER_IP,
                  dst=SERVER_IP if random.random() < 0.5 else CLIENT_IP, ttl=ttl) /
               TCP(sport=random.randint(1024, 65535), dport=80))
    elif proto_pkt == "udp":
        pkt = (Ether() /
               IP(src=CLIENT_IP if random.random() < 0.5 else SERVER_IP,
                  dst=SERVER_IP if random.random() < 0.5 else CLIENT_IP, ttl=ttl) /
               UDP(sport=random.randint(1024, 65535), dport=53) /
               Raw(load=b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"))
    else:
        pkt = (Ether() /
               IP(src=CLIENT_IP if random.random() < 0.5 else SERVER_IP,
                  dst=SERVER_IP if random.random() < 0.5 else CLIENT_IP, ttl=ttl) /
               ICMP())

    paquetes_normales.append(pkt)
    paquetes_todos.append(pkt)

# ── 2. Tráfico fragmentado ────────────────────────────────
# Fragmento 1: MF=1, offset=0
frag1 = (Ether() /
          IP(src=CLIENT_IP, dst=SERVER_IP,
             ttl=64, id=0xABCD, flags="MF", frag=0) /
          Raw(load=b"A" * 1480))
# Fragmento 2: MF=0, offset=185 (1480/8)
frag2 = (Ether() /
          IP(src=CLIENT_IP, dst=SERVER_IP,
             ttl=64, id=0xABCD, flags=0, frag=185) /
          Raw(load=b"B" * 100))

paquetes_todos.extend([frag1, frag2])
print(f"  ✔ 2 fragmentos IP (ID=0xABCD) incluidos")

# ── 3. Tráfico spoofed (TTL anómalo) ─────────────────────
ips_spoofed = []
for i in range(40):
    src_falsa = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    ttl_malo  = random.choice(
        list(range(1, 59)) +
        list(range(70, 123)) +
        list(range(133, 250))
    )
    pkt = (Ether() /
           IP(src=src_falsa, dst=SERVER_IP,
              ttl=ttl_malo) /
           ICMP() /
           Raw(load=b"SPOOFED"))
    paquetes_spoofed.append(pkt)
    paquetes_todos.append(pkt)
    ips_spoofed.append(src_falsa)

# Mezclar para que no sean todos juntos
random.shuffle(paquetes_todos)

# ── Guardar archivos ──────────────────────────────────────
wrpcap(os.path.join(OUTPUT_DIR, "trafico_normal.pcap"),  paquetes_normales)
wrpcap(os.path.join(OUTPUT_DIR, "trafico_spoofed.pcap"), paquetes_spoofed)
wrpcap(os.path.join(OUTPUT_DIR, "experimento_mixto.pcap"), paquetes_todos)

# Guardar lista de IPs spoofed para referencia
with open(os.path.join(OUTPUT_DIR, "ips_spoofed.txt"), "w") as f:
    f.write("# IPs spoofed usadas en experimento_mixto.pcap\n")
    for ip in ips_spoofed:
        f.write(ip + "\n")

print(f"  ✔ trafico_normal.pcap  — {len(paquetes_normales)} paquetes legítimos")
print(f"  ✔ trafico_spoofed.pcap — {len(paquetes_spoofed)} paquetes spoofed")
print(f"  ✔ experimento_mixto.pcap — {len(paquetes_todos)} paquetes mezclados")
print(f"  ✔ ips_spoofed.txt — lista de IPs falsificadas")
print(f"\n[✔] Capturas guardadas en: {os.path.abspath(OUTPUT_DIR)}/")
print(f"\nValidar con:")
print(f"  tshark -r pcap_samples/trafico_normal.pcap | head -20")
print(f"  tshark -r pcap_samples/experimento_mixto.pcap -T fields -e ip.ttl | sort -n | uniq -c")
