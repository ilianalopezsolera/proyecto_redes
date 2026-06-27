#!/usr/bin/env python3
"""
=============================================================================
Tests automatizados — M2 Parser IP y M3 Detector de Anomalías
IF5000 — Redes y Comunicación de Datos | Grupo 3 — Protocolo IP
=============================================================================
Ejecutar:  python3 tests/test_m2_parser.py
No requiere sudo (trabaja con bytes preconstruidos).
=============================================================================
"""

import sys
import os
import struct
import socket

MODULOS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'módulos'))
sys.path.insert(0, MODULOS_DIR)
from m2_parser_ip import parsear_datagrama, calcular_checksum, DatagramaIP, TTL_OS
from m3_detector_anomalias import ttl_es_anomalo, TTL_ESTANDAR

PASS = "\033[92m✔ PASS\033[0m"
FAIL = "\033[91m✘ FAIL\033[0m"


def construir_cabecera_ip(
    src="192.168.100.10", dst="192.168.100.20",
    ttl=64, proto=1, total_len=40,
    ident=0x1234, flags=0, frag_offset=0
) -> bytes:
    """Construye una cabecera IP mínima válida con checksum correcto."""
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)

    # Empacar con checksum = 0 primero
    cabecera = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,          # VHL: Version=4, IHL=5
        0x00,          # ToS
        total_len,
        ident,
        (flags << 13) | frag_offset,
        ttl,
        proto,
        0,             # checksum = 0 para calcular
        src_b,
        dst_b,
    )
    # Calcular e insertar checksum real
    ck = calcular_checksum(cabecera)
    cabecera = cabecera[:10] + struct.pack("!H", ck) + cabecera[12:]
    return cabecera


# ─────────────────────────────────────────────────────────────
# Suite de tests
# ─────────────────────────────────────────────────────────────

resultados = []

def test(nombre, condicion, detalle=""):
    estado = PASS if condicion else FAIL
    print(f"  {estado}  {nombre}")
    if not condicion and detalle:
        print(f"         → {detalle}")
    resultados.append(condicion)


print("=" * 60)
print(" SUITE DE TESTS — IF5000 Grupo 3 — Protocolo IP")
print("=" * 60)

# ── Test 1: Parseo básico ──────────────────────────────────
print("\n[1] Parser IP — extracción de campos (RFC 791)")
raw = construir_cabecera_ip(src="10.0.0.1", dst="10.0.0.2", ttl=64, proto=1)
d = parsear_datagrama(raw + b'\x00' * 20, 1)

test("Version = 4",        d is not None and d.version == 4)
test("IHL = 5",            d is not None and d.ihl == 5)
test("TTL = 64",           d is not None and d.ttl == 64)
test("Protocolo = 1 (ICMP)", d is not None and d.protocolo == 1)
test("SRC = 10.0.0.1",     d is not None and d.src == "10.0.0.1")
test("DST = 10.0.0.2",     d is not None and d.dst == "10.0.0.2")

# ── Test 2: Verificación de checksum ──────────────────────
print("\n[2] Verificación de Header Checksum (RFC 791 §3.1)")
test("Checksum válido",    d is not None and d.checksum_ok,
     f"checksum_hdr={d.checksum_hdr:#06x} calc={d.checksum_calc:#06x}" if d else "")

# Corromper el checksum
if d:
    raw_corrupto = bytearray(raw + b'\x00' * 20)
    raw_corrupto[10] ^= 0xFF   # invertir byte alto del checksum
    d_corrupto = parsear_datagrama(bytes(raw_corrupto), 2)
    test("Checksum inválido detectado",
         d_corrupto is not None and not d_corrupto.checksum_ok)

# ── Test 3: Cálculo de checksum independiente ─────────────
print("\n[3] Función calcular_checksum (ones' complement)")
# RFC 791: el checksum de la cabecera completa (incluyendo el campo checksum)
# debe dar 0xFFFF (complemento a uno de 0).
if d:
    ck_verificacion = calcular_checksum(raw[:20])
    # La suma con el propio checksum incluido debe dar 0 en complemento a uno
    # (práctica estándar: resultado = 0 si es válido, o 0xFFFF en variante)
    test("Suma total cabecera es 0x0000 o 0xFFFF",
         ck_verificacion in (0x0000, 0xFFFF),
         f"resultado={ck_verificacion:#06x}")

# ── Test 4: Detección de fragmentación ────────────────────
print("\n[4] Detección de fragmentación (flags MF / Fragment Offset)")

# Paquete con MF=1 (hay más fragmentos)
raw_mf = construir_cabecera_ip(flags=0b001, frag_offset=0, total_len=40)
d_mf = parsear_datagrama(raw_mf + b'\x00' * 20, 3)
test("Flag MF=1 detectado",  d_mf is not None and d_mf.flag_mf == 1)
test("es_fragmento=True",    d_mf is not None and d_mf.es_fragmento)

# Último fragmento: MF=0, frag_offset>0
raw_last = construir_cabecera_ip(flags=0b000, frag_offset=185, total_len=40)
d_last = parsear_datagrama(raw_last + b'\x00' * 20, 4)
test("Último fragmento detectado",   d_last is not None and d_last.es_ultimo_frag)
test("frag_offset = 185",            d_last is not None and d_last.frag_offset == 185)

# Paquete sin fragmentar
raw_nofrag = construir_cabecera_ip(flags=0b010, frag_offset=0, total_len=40)
d_nofrag = parsear_datagrama(raw_nofrag + b'\x00' * 20, 5)
test("Paquete no fragmentado",  d_nofrag is not None and not d_nofrag.es_fragmento)
test("Flag DF=1",               d_nofrag is not None and d_nofrag.flag_df == 1)

# ── Test 5: Detección de TTL anómalo ──────────────────────
print("\n[5] Detector de TTL anómalo (M3)")

# TTLs legítimos (deben pasar como normales)
for ttl_leg in [64, 63, 60, 128, 127, 124, 255, 254, 251]:
    anomalo, _ = ttl_es_anomalo(ttl_leg)
    test(f"TTL={ttl_leg} → legítimo", not anomalo)

# TTLs anómalos (deben ser detectados)
for ttl_bad in [1, 30, 70, 100, 133, 200, 249]:
    anomalo, razon = ttl_es_anomalo(ttl_bad)
    test(f"TTL={ttl_bad} → anómalo detectado", anomalo, razon)

# ── Test 6: Paquete no-IPv4 ───────────────────────────────
print("\n[6] Robustez — entradas inválidas")
test("Bytes vacíos → None",            parsear_datagrama(b"", 0) is None)
test("Bytes cortos (<20) → None",      parsear_datagrama(b"\x45\x00\x00", 0) is None)
test("Versión IPv6 → None",
     parsear_datagrama(b"\x60" + b"\x00"*19 + b"\x00"*20, 0) is None)

# ── Resumen ───────────────────────────────────────────────
print("\n" + "=" * 60)
aprobados = sum(resultados)
total     = len(resultados)
print(f" Resultado: {aprobados}/{total} tests aprobados", end="")
if aprobados == total:
    print(f"  \033[92m— TODOS APROBADOS ✔\033[0m")
else:
    print(f"  \033[91m— {total - aprobados} FALLIDOS ✘\033[0m")
print("=" * 60)
sys.exit(0 if aprobados == total else 1)
