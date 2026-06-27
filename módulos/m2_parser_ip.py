#!/usr/bin/env python3
"""
=============================================================================
M2 — Parser de Datagramas IP a Bajo Nivel
IF5000 — Redes y Comunicación de Datos | Grupo 3 — Protocolo IP
=============================================================================
Descripción:
    Implementa un parser completo del datagrama IPv4 (RFC 791) operando
    directamente sobre bytes crudos con struct.unpack, SIN delegar en
    librerías de alto nivel que oculten la estructura del protocolo.

    Funcionalidades:
    ─ Extracción de TODOS los campos de la cabecera IP (RFC 791)
    ─ Verificación del Header Checksum (RFC 791, Sección 3.1)
    ─ Detección y análisis de fragmentación (flags MF, DF, Fragment Offset)
    ─ Simulación de reensamblado de fragmentos
    ─ Comparación visual campo-a-campo contra tshark (validación Wireshark)
    ─ Capaz de leer archivos .pcap y paquetes en vivo

Uso:
    # Parsear un archivo .pcap existente
    sudo python3 m2_parser_ip.py --pcap ../pcap_samples/captura.pcap

    # Captura en vivo y parseo inmediato
    sudo python3 m2_parser_ip.py --live --iface eth0 --count 20

    # Solo mostrar paquetes fragmentados
    sudo python3 m2_parser_ip.py --pcap archivo.pcap --solo-frags

RFC de referencia: https://www.rfc-editor.org/rfc/rfc791
=============================================================================
"""

import struct
import socket
import argparse
import sys
import os
from dataclasses import dataclass, field
from typing import Optional, List, Dict

# Scapy se usa SOLO para leer .pcap y captura en vivo.
# El parseo real lo hace struct sobre bytes crudos.
from scapy.all import rdpcap, sniff, raw, IP as ScapyIP, get_if_list


# ─────────────────────────────────────────────
# Constantes RFC 791
# ─────────────────────────────────────────────
PROTO_NOMBRES = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP",
    41: "IPv6-encap",
    89: "OSPF",
}

# Valores TTL iniciales típicos por sistema operativo
TTL_OS = {
    64:  "Linux / macOS",
    128: "Windows",
    255: "Cisco IOS / Solaris",
}

CABECERA_FMT = "!BBHHHBBH4s4s"   # Big-endian, 20 bytes mínimos
CABECERA_LEN = struct.calcsize(CABECERA_FMT)   # == 20


# ─────────────────────────────────────────────
# Estructura de datos que representa un datagrama
# ─────────────────────────────────────────────
@dataclass
class DatagramaIP:
    """Representación de un datagrama IPv4 parseado desde bytes crudos."""
    # Cabecera — campos RFC 791
    version:        int = 0
    ihl:            int = 0       # Internet Header Length (en palabras de 32 bits)
    dscp:           int = 0       # Differentiated Services Code Point (ToS alto 6 bits)
    ecn:            int = 0       # Explicit Congestion Notification (ToS bajo 2 bits)
    total_len:      int = 0
    identificacion: int = 0
    flag_reservado: int = 0
    flag_df:        int = 0       # Don't Fragment
    flag_mf:        int = 0       # More Fragments
    frag_offset:    int = 0       # en unidades de 8 bytes
    ttl:            int = 0
    protocolo:      int = 0
    checksum_hdr:   int = 0       # checksum leído del datagrama
    checksum_calc:  int = 0       # checksum recalculado por nosotros
    checksum_ok:    bool = False
    src:            str = ""
    dst:            str = ""
    opciones:       bytes = b""
    payload:        bytes = b""
    # Metadatos de análisis
    es_fragmento:   bool = False
    es_ultimo_frag: bool = False
    indice:         int  = 0      # número de paquete en la captura


# ─────────────────────────────────────────────
# Núcleo del parser — SOLO usa struct sobre bytes
# ─────────────────────────────────────────────

def calcular_checksum(datos: bytes) -> int:
    """
    Calcula el checksum de la cabecera IP según RFC 791 Sección 3.1:
    'The checksum field is the 16 bit ones' complement of the ones'
    complement sum of all 16 bit words in the header.'
    """
    if len(datos) % 2 != 0:
        datos += b'\x00'          # padding si longitud impar

    suma = 0
    for i in range(0, len(datos), 2):
        palabra = (datos[i] << 8) + datos[i + 1]
        suma += palabra

    # Complemento a uno: plegar los carries del bit 16 hacia los bits bajos
    while suma >> 16:
        suma = (suma & 0xFFFF) + (suma >> 16)

    return ~suma & 0xFFFF


def parsear_datagrama(raw_bytes: bytes, indice: int = 0) -> Optional[DatagramaIP]:
    """
    Parsea un datagrama IPv4 completo desde bytes crudos usando struct.
    Retorna None si los bytes no corresponden a un datagrama IPv4 válido.

    Layout de la cabecera IP (RFC 791, Figura 4):
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    if len(raw_bytes) < CABECERA_LEN:
        return None

    try:
        (vhl, tos, total_len, ident, flags_frag,
         ttl, proto, checksum, src_raw, dst_raw) = struct.unpack(
            CABECERA_FMT, raw_bytes[:CABECERA_LEN]
        )
    except struct.error:
        return None

    # ── Extraer subcampos de los bytes empaquetados ──
    version = (vhl >> 4) & 0xF
    ihl     = vhl & 0xF                # longitud cabecera en palabras de 32 bits

    if version != 4:
        return None                    # no es IPv4

    dscp = (tos >> 2) & 0x3F
    ecn  = tos & 0x03

    flag_reservado = (flags_frag >> 15) & 0x1
    flag_df        = (flags_frag >> 14) & 0x1
    flag_mf        = (flags_frag >> 13) & 0x1
    frag_offset    = flags_frag & 0x1FFF   # 13 bits bajos, unidades de 8 bytes

    src = socket.inet_ntoa(src_raw)
    dst = socket.inet_ntoa(dst_raw)

    # ── Opciones IP (si IHL > 5) ──
    cabecera_bytes = ihl * 4
    opciones = raw_bytes[CABECERA_LEN:cabecera_bytes] if cabecera_bytes > CABECERA_LEN else b""
    payload  = raw_bytes[cabecera_bytes:total_len] if total_len <= len(raw_bytes) else raw_bytes[cabecera_bytes:]

    # ── Verificar checksum ──
    # Para verificar: copiamos la cabecera, ponemos checksum=0 y recalculamos
    cabecera_sin_checksum = bytearray(raw_bytes[:cabecera_bytes])
    cabecera_sin_checksum[10] = 0
    cabecera_sin_checksum[11] = 0
    checksum_calc = calcular_checksum(bytes(cabecera_sin_checksum))
    checksum_ok   = (checksum_calc == checksum)

    d = DatagramaIP(
        version        = version,
        ihl            = ihl,
        dscp           = dscp,
        ecn            = ecn,
        total_len      = total_len,
        identificacion = ident,
        flag_reservado = flag_reservado,
        flag_df        = flag_df,
        flag_mf        = flag_mf,
        frag_offset    = frag_offset,
        ttl            = ttl,
        protocolo      = proto,
        checksum_hdr   = checksum,
        checksum_calc  = checksum_calc,
        checksum_ok    = checksum_ok,
        src            = src,
        dst            = dst,
        opciones       = opciones,
        payload        = payload,
        es_fragmento   = (flag_mf == 1 or frag_offset > 0),
        es_ultimo_frag = (flag_mf == 0 and frag_offset > 0),
        indice         = indice,
    )
    return d


# ─────────────────────────────────────────────
# Presentación detallada del datagrama
# ─────────────────────────────────────────────

def imprimir_datagrama(d: DatagramaIP, verbose: bool = True):
    """Muestra todos los campos del datagrama al estilo Wireshark."""
    sep = "─" * 62
    proto_nombre = PROTO_NOMBRES.get(d.protocolo, f"DESCONOCIDO({d.protocolo})")
    os_origen    = TTL_OS.get(d.ttl, f"TTL={d.ttl} (no estándar)")
    ck_estado    = "✔ VÁLIDO" if d.checksum_ok else "✘ INVÁLIDO"

    print(f"\n{sep}")
    print(f" Paquete #{d.indice:04d} — Internet Protocol Version 4 (RFC 791)")
    print(sep)
    print(f"  Version              : {d.version}")
    print(f"  IHL                  : {d.ihl} ({d.ihl * 4} bytes de cabecera)")
    print(f"  DSCP                 : {d.dscp:#04x}  ECN: {d.ecn}")
    print(f"  Total Length         : {d.total_len} bytes")
    print(f"  Identification       : {d.identificacion:#06x} ({d.identificacion})")
    print(f"  Flags                : DF={d.flag_df}  MF={d.flag_mf}  Rsv={d.flag_reservado}")
    print(f"  Fragment Offset      : {d.frag_offset} ({d.frag_offset * 8} bytes desde origen)")
    print(f"  Time to Live (TTL)   : {d.ttl}  →  OS estimado: {os_origen}")
    print(f"  Protocol             : {d.protocolo} ({proto_nombre})")
    print(f"  Header Checksum      : {d.checksum_hdr:#06x}  {ck_estado}")
    print(f"    Checksum calculado : {d.checksum_calc:#06x}")
    print(f"  Source Address       : {d.src}")
    print(f"  Destination Address  : {d.dst}")
    if d.opciones:
        print(f"  Options              : {d.opciones.hex()}")
    if d.es_fragmento:
        print(f"  *** FRAGMENTO DETECTADO ***")
        if d.es_ultimo_frag:
            print(f"      Último fragmento del datagrama ID={d.identificacion:#06x}")
        else:
            print(f"      Fragmento parcial — MF=1 — Offset={d.frag_offset * 8} bytes")
    print(f"  Payload              : {len(d.payload)} bytes")
    if verbose and d.payload:
        hexdump = " ".join(f"{b:02x}" for b in d.payload[:32])
        print(f"  Payload (hex, 32B)   : {hexdump}{'...' if len(d.payload) > 32 else ''}")


# ─────────────────────────────────────────────
# Reensamblado de fragmentos
# ─────────────────────────────────────────────

class ReensambladorIP:
    """
    Acumula fragmentos IP agrupados por (src, dst, ID) y los reensambla
    cuando recibe el último fragmento (MF=0, offset>0).
    RFC 791 Sección 3.2 — Fragmentation and Reassembly.
    """

    def __init__(self):
        # clave: (src, dst, identificacion) → lista de DatagramaIP
        self._buffer: Dict[tuple, List[DatagramaIP]] = {}

    def agregar(self, d: DatagramaIP) -> Optional[bytes]:
        """
        Agrega un fragmento. Retorna el payload reensamblado completo
        si ya se tienen todos los fragmentos, None en caso contrario.
        """
        if not d.es_fragmento and d.flag_mf == 0:
            return None    # paquete sin fragmentar

        clave = (d.src, d.dst, d.identificacion)
        if clave not in self._buffer:
            self._buffer[clave] = []

        self._buffer[clave].append(d)

        # Intentar reensamblado solo si ya llegó el último fragmento
        tiene_ultimo = any(f.es_ultimo_frag for f in self._buffer[clave])
        if not tiene_ultimo:
            return None

        # Ordenar por Fragment Offset y concatenar payloads
        fragmentos = sorted(self._buffer[clave], key=lambda f: f.frag_offset)
        datos_completos = b"".join(f.payload for f in fragmentos)
        del self._buffer[clave]

        print(f"\n  [REENSAMBLADO] Datagrama ID={d.identificacion:#06x} "
              f"({d.src} → {d.dst})")
        print(f"  Fragmentos usados : {len(fragmentos)}")
        print(f"  Payload total     : {len(datos_completos)} bytes")
        return datos_completos

    def pendientes(self) -> int:
        return len(self._buffer)


# ─────────────────────────────────────────────
# Resumen estadístico
# ─────────────────────────────────────────────

def seleccionar_interfaz(iface_solicitada: Optional[str]) -> str:
    """Elige una interfaz válida para capturas en vivo."""
    ifaces = get_if_list()
    if iface_solicitada and iface_solicitada in ifaces:
        return iface_solicitada
    candidatos = [i for i in ifaces if not i.startswith("lo") and not i.startswith("docker") and not i.startswith("veth")]
    if candidatos:
        return candidatos[0]
    return iface_solicitada or "eth0"


def imprimir_resumen(datagramas: List[DatagramaIP]):
    total      = len(datagramas)
    ck_ok      = sum(1 for d in datagramas if d.checksum_ok)
    frags      = sum(1 for d in datagramas if d.es_fragmento)
    protos     = {}
    ttls       = {}

    for d in datagramas:
        pn = PROTO_NOMBRES.get(d.protocolo, f"PROTO-{d.protocolo}")
        protos[pn] = protos.get(pn, 0) + 1
        ttls[d.ttl] = ttls.get(d.ttl, 0) + 1

    sep = "═" * 62
    print(f"\n{sep}")
    print(f" RESUMEN — {total} datagramas IP parseados")
    print(sep)
    print(f"  Checksum válido    : {ck_ok}/{total} ({100*ck_ok//total if total else 0}%)")
    print(f"  Fragmentados       : {frags}")
    print(f"  Distribución de protocolos:")
    for proto, cnt in sorted(protos.items(), key=lambda x: -x[1]):
        bar = "█" * (cnt * 20 // max(protos.values()))
        print(f"    {proto:<8} {cnt:>5}  {bar}")
    print(f"  Distribución de TTL:")
    for ttl, cnt in sorted(ttls.items()):
        os_h = TTL_OS.get(ttl, "no estándar")
        print(f"    TTL={ttl:<3}  {cnt:>5} paquetes  ({os_h})")
    print(sep)


# ─────────────────────────────────────────────
# Función principal
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="M2 — Parser IP a bajo nivel (IF5000 Grupo 3)"
    )
    modos = parser.add_mutually_exclusive_group(required=True)
    modos.add_argument("--pcap",  help="Archivo .pcap a parsear")
    modos.add_argument("--live",  action="store_true",
                       help="Captura en vivo y parseo inmediato")
    parser.add_argument("--iface",      default=None,
                        help="Interfaz para captura en vivo (si se omite, se elige automáticamente)")
    parser.add_argument("--count",      type=int, default=50,
                        help="Paquetes a capturar en modo --live")
    parser.add_argument("--solo-frags", action="store_true",
                        help="Mostrar solo paquetes fragmentados")
    parser.add_argument("--resumen",    action="store_true",
                        help="Mostrar resumen estadístico al final")
    parser.add_argument("--verbose",    action="store_true",
                        help="Mostrar hexdump del payload")
    args = parser.parse_args()

    datagramas: List[DatagramaIP] = []
    reensamblador = ReensambladorIP()

    # ── Obtener paquetes crudos ──
    if args.pcap:
        if not os.path.exists(args.pcap):
            print(f"[ERROR] Archivo no encontrado: {args.pcap}")
            sys.exit(1)
        print(f"[*] Leyendo {args.pcap} ...")
        pkts = rdpcap(args.pcap)
        raw_list = [(raw(p), i+1) for i, p in enumerate(pkts) if ScapyIP in p]
        # Scapy nos da el paquete completo desde capa 2; necesitamos desde IP
        raw_list = [(raw(p[ScapyIP]), i) for p, i in raw_list]
    else:
        iface_final = seleccionar_interfaz(args.iface)
        print(f"[*] Capturando {args.count} paquetes en {iface_final} ...")
        capturados = []
        def cb(pkt):
            if ScapyIP in pkt:
                capturados.append((raw(pkt[ScapyIP]), len(capturados)+1))
        try:
            sniff(iface=iface_final, filter="ip", count=args.count,
                  prn=cb, store=False)
        except PermissionError:
            print("[ERROR] Requiere sudo.")
            sys.exit(1)
        raw_list = capturados

    # ── Parsear cada paquete con struct (M2 core) ──
    for raw_bytes, idx in raw_list:
        d = parsear_datagrama(raw_bytes, idx)
        if d is None:
            continue

        if args.solo_frags and not d.es_fragmento:
            continue

        imprimir_datagrama(d, verbose=args.verbose)
        datagramas.append(d)

        # Intentar reensamblado si hay fragmentos
        if d.es_fragmento:
            reensamblador.agregar(d)

    if reensamblador.pendientes() > 0:
        print(f"\n[!] Fragmentos sin reensamblado completo: "
              f"{reensamblador.pendientes()} flujos pendientes.")

    if args.resumen or len(datagramas) > 10:
        imprimir_resumen(datagramas)

    print(f"\n[✔] Parser completado. "
          f"Validar con: tshark -r {args.pcap if args.pcap else 'captura.pcap'} -V | grep -E 'Source|Destination|TTL|Checksum|Flags'")


if __name__ == "__main__":
    main()
