

#!/usr/bin/env python3

"""
=============================================================================
M3 — Detector de Anomalías IP: Spoofing y TTL Anómalo
IF5000 — Redes y Comunicación de Datos | Grupo 3 — Protocolo IP
=============================================================================
Descripción:
    Implementa dos funciones principales:

    1. GENERADOR de tráfico spoofed:
       Construye datagramas IP con Source Address falsificada y TTL anómalo
       usando Scapy IP() sobre sockets RAW, simulando el ataque de IP Spoofing.

    2. DETECTOR de anomalías TTL:
       Analiza flujos de paquetes y marca como sospechosos aquellos con TTL
       que no corresponde a ningún sistema operativo conocido, ajustado por
       el número de saltos esperados (hops) en la red controlada.
       Reporta métricas cuantitativas: TPR, FPR, latencia de detección.

Uso:
    # Generar tráfico spoofed (requiere sudo)
    sudo python3 m3_detector_anomalias.py --modo generar \
        --dst 192.168.100.20 --count 50

    # Detectar anomalías en una captura
    sudo python3 m3_detector_anomalias.py --modo detectar \
        --pcap ../pcap_samples/captura.pcap

    # Experimento completo (generar + detectar + métricas)
    sudo python3 m3_detector_anomalias.py --modo experimento \
        --iface enp0s8 --dst 192.168.100.20

RFC de referencia: https://www.rfc-editor.org/rfc/rfc791
=============================================================================
"""

import argparse
import time
import random
import datetime
import os
import sys
from dataclasses import dataclass, field
from typing import List, Tuple, Optional

from scapy.all import (
    IP, TCP, UDP, ICMP, Raw, send, sniff, rdpcap,
    get_if_addr, get_if_list, raw as scapy_raw
)

# Importar nuestro parser de bajo nivel (M2)
sys.path.insert(0, os.path.dirname(__file__))
from m2_parser_ip import parsear_datagrama, DatagramaIP, TTL_OS


# ─────────────────────────────────────────────
# Constantes del detector
# ─────────────────────────────────────────────

# TTL iniciales estándar conocidos (Linux, Windows, Cisco)
TTL_ESTANDAR = {64, 128, 255}

# Máximo de saltos que consideramos en nuestra red de VMs (rango conservador)
MAX_HOPS_RED = 5

# Rangos de TTL legítimos: valor estándar menos MAX_HOPS_RED
TTL_RANGOS_LEGITIMOS = [
    (ttl - MAX_HOPS_RED, ttl) for ttl in TTL_ESTANDAR
]

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "pcap_samples")


# ─────────────────────────────────────────────
# Estructuras de resultado
# ─────────────────────────────────────────────

@dataclass
class ResultadoAnalisis:
    """Resultado del análisis de un paquete individual."""
    indice:       int
    src:          str
    dst:          str
    ttl:          int
    es_anomalo:   bool
    es_spoofed:   bool          # etiqueta real (para experimento controlado)
    latencia_ms:  float = 0.0
    razon:        str   = ""


@dataclass
class MetricasDeteccion:
    """Métricas de efectividad del detector (TP, FP, FN, TN)."""
    tp: int = 0    # Verdaderos Positivos: spoofed detectado como anomalo
    fp: int = 0    # Falsos Positivos: legítimo marcado como anomalo
    fn: int = 0    # Falsos Negativos: spoofed NO detectado
    tn: int = 0    # Verdaderos Negativos: legítimo marcado como legítimo
    latencias: List[float] = field(default_factory=list)

    @property
    def total(self): return self.tp + self.fp + self.fn + self.tn

    @property
    def tpr(self):
        """True Positive Rate = TP / (TP + FN)"""
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def fpr(self):
        """False Positive Rate = FP / (FP + TN)"""
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) > 0 else 0.0

    @property
    def precision(self):
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def latencia_promedio(self):
        return sum(self.latencias) / len(self.latencias) if self.latencias else 0.0

    @property
    def latencia_max(self):
        return max(self.latencias) if self.latencias else 0.0


# ─────────────────────────────────────────────
# GENERADOR de tráfico spoofed (IP Spoofing)
# ─────────────────────────────────────────────

def seleccionar_interfaz(iface_solicitada: str = None) -> str:
    """Elige una interfaz válida para generar o capturar tráfico."""
    ifaces = get_if_list()
    if iface_solicitada and iface_solicitada in ifaces:
        return iface_solicitada
    candidatos = [i for i in ifaces if not i.startswith("lo") and not i.startswith("docker") and not i.startswith("veth")]
    if candidatos:
        return candidatos[0]
    return iface_solicitada or "eth0"


def generar_trafico_spoofed(
    dst: str,
    count: int = 50,
    iface: str = None,
    verbose: bool = True
) -> List[str]:
    """
    Genera 'count' paquetes con Source IP falsificada y TTL anómalo.
    Retorna lista de IPs spoofed usadas.

    El TTL se elige deliberadamente fuera de los rangos legítimos
    para facilitar la detección experimental.
    """
    print("=" * 62)
    print(" M3 — GENERADOR de Tráfico IP Spoofed")
    print("=" * 62)
    print(f" Destino   : {dst}")
    print(f" Paquetes  : {count}")
    print("-" * 62)

    ips_spoofed = []
    for i in range(count):
        # IP de origen falsificada: rango privado aleatorio
        src_falsa = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        # TTL anómalo: valores que NO corresponden a ningún OS estándar
        # (fuera de los rangos legítimos)
        ttl_anomalo = random.choice(
            list(range(1, 59)) +   # demasiado bajo para ser legítimo post-hops
            list(range(70, 123)) + # entre Linux y Windows
            list(range(133, 250))  # entre Windows y Cisco
        )

        pkt = (
            IP(src=src_falsa, dst=dst, ttl=ttl_anomalo) /
            ICMP() /
            Raw(load=b"IF5000-SPOOFED-PKT")
        )

        t0 = time.perf_counter()
        send(pkt, iface=iface, verbose=False)
        t1 = time.perf_counter()

        ips_spoofed.append(src_falsa)
        if verbose:
            print(f"  [{i+1:03d}] src={src_falsa:<18} ttl={ttl_anomalo:<3} "
                  f"enviado en {(t1-t0)*1000:.2f}ms")

        time.sleep(0.01)   # pequeña pausa para no saturar

    print(f"\n[✔] {count} paquetes spoofed enviados a {dst}")
    return ips_spoofed


def generar_trafico_legitimo(
    dst: str,
    count: int = 50,
    iface: str = None
):
    """Genera tráfico ICMP legítimo con TTL estándar (línea base)."""
    print(f"\n[*] Generando {count} paquetes legítimos (línea base) → {dst}")
    for i in range(count):
        ttl_legitimo = random.choice([64, 128])
        pkt = IP(dst=dst, ttl=ttl_legitimo) / ICMP() / Raw(load=b"IF5000-LEGITIMO")
        send(pkt, iface=iface, verbose=False)
        time.sleep(0.005)
    print(f"[✔] {count} paquetes legítimos enviados.")


# ─────────────────────────────────────────────
# DETECTOR de anomalías TTL
# ─────────────────────────────────────────────

def ttl_es_anomalo(ttl: int) -> Tuple[bool, str]:
    """
    Determina si un valor de TTL es anómalo.
    Un TTL es legítimo si cae dentro de alguno de los rangos:
        [ttl_estandar - MAX_HOPS_RED, ttl_estandar]
    para algún TTL estándar conocido.
    Retorna (es_anomalo, razón).
    """
    for (limite_inf, limite_sup) in TTL_RANGOS_LEGITIMOS:
        if limite_inf <= ttl <= limite_sup:
            return False, f"TTL={ttl} dentro del rango legítimo [{limite_inf}-{limite_sup}]"

    os_mas_cercano = min(TTL_ESTANDAR, key=lambda t: abs(t - ttl))
    return True, (
        f"TTL={ttl} fuera de todos los rangos legítimos. "
        f"OS más cercano sería {TTL_OS[os_mas_cercano]} (TTL={os_mas_cercano}) "
        f"pero la diferencia es {abs(os_mas_cercano - ttl)} hops "
        f"(máx. permitido: {MAX_HOPS_RED})"
    )


def analizar_paquete(raw_bytes: bytes, indice: int,
                     es_spoofed_real: bool = False) -> Optional[ResultadoAnalisis]:
    """Parsea y analiza un paquete individual. Retorna su resultado."""
    t0 = time.perf_counter()
    d  = parsear_datagrama(raw_bytes, indice)
    if d is None:
        return None

    anomalo, razon = ttl_es_anomalo(d.ttl)
    t1 = time.perf_counter()

    return ResultadoAnalisis(
        indice      = indice,
        src         = d.src,
        dst         = d.dst,
        ttl         = d.ttl,
        es_anomalo  = anomalo,
        es_spoofed  = es_spoofed_real,
        latencia_ms = (t1 - t0) * 1000,
        razon       = razon,
    )


def detectar_anomalias_pcap(
    ruta_pcap: str,
    etiquetas_spoofed: set = None,
    verbose: bool = True
) -> Tuple[List[ResultadoAnalisis], MetricasDeteccion]:
    """
    Analiza todos los paquetes IP de un .pcap y calcula métricas de detección.
    'etiquetas_spoofed': conjunto de IPs src que se sabe que son spoofed
                         (para el experimento controlado).
    """
    from scapy.all import rdpcap, IP as ScapyIP

    if not os.path.exists(ruta_pcap):
        print(f"[ERROR] Archivo no encontrado: {ruta_pcap}")
        sys.exit(1)

    pkts = rdpcap(ruta_pcap)
    resultados: List[ResultadoAnalisis] = []
    metricas = MetricasDeteccion()

    print("=" * 62)
    print(f" M3 — DETECTOR de Anomalías TTL")
    print(f" Archivo: {ruta_pcap}")
    print(f" Paquetes: {len(pkts)}")
    print("=" * 62)
    print(f"{'#':<5} {'SRC':<18} {'DST':<18} {'TTL':<5} {'ESTADO':<12} {'LATENCIA'}")
    print("-" * 62)

    for i, pkt in enumerate(pkts):
        if ScapyIP not in pkt:
            continue

        raw_bytes  = scapy_raw(pkt[ScapyIP])
        src        = pkt[ScapyIP].src
        es_spoofed = src in etiquetas_spoofed if etiquetas_spoofed else False
        resultado  = analizar_paquete(raw_bytes, i+1, es_spoofed)
        if resultado is None:
            continue

        resultados.append(resultado)
        metricas.latencias.append(resultado.latencia_ms)

        # Calcular TP/FP/FN/TN
        if resultado.es_anomalo and resultado.es_spoofed:
            metricas.tp += 1
        elif resultado.es_anomalo and not resultado.es_spoofed:
            metricas.fp += 1
        elif not resultado.es_anomalo and resultado.es_spoofed:
            metricas.fn += 1
        else:
            metricas.tn += 1

        estado = "⚠ ANOMALO" if resultado.es_anomalo else "✔ normal"
        if verbose or resultado.es_anomalo:
            print(f"  {i+1:<4} {resultado.src:<18} {resultado.dst:<18} "
                  f"{resultado.ttl:<5} {estado:<12} {resultado.latencia_ms:.3f}ms")

    return resultados, metricas


# ─────────────────────────────────────────────
# Reporte de métricas
# ─────────────────────────────────────────────

def imprimir_metricas(m: MetricasDeteccion):
    """Imprime el reporte final de métricas de detección."""
    sep = "═" * 62
    print(f"\n{sep}")
    print(f" MÉTRICAS DE DETECCIÓN — M3 Detector Anomalías IP")
    print(sep)
    print(f"  Total de paquetes analizados : {m.total}")
    print()
    print(f"  Matriz de confusión:")
    print(f"  ┌─────────────────────┬────────────┬────────────┐")
    print(f"  │                     │ Real=Anomalo│ Real=Normal│")
    print(f"  ├─────────────────────┼────────────┼────────────┤")
    print(f"  │ Detectado=Anomalo   │  TP = {m.tp:<5} │  FP = {m.fp:<5} │")
    print(f"  │ Detectado=Normal    │  FN = {m.fn:<5} │  TN = {m.tn:<5} │")
    print(f"  └─────────────────────┴────────────┴────────────┘")
    print()
    print(f"  True Positive Rate  (TPR/Recall) : {m.tpr*100:.1f}%  (objetivo ≥ 90%)")
    print(f"  False Positive Rate (FPR)         : {m.fpr*100:.1f}%  (objetivo ≤  5%)")
    print(f"  Precision                         : {m.precision*100:.1f}%")
    print()
    print(f"  Latencia promedio de detección    : {m.latencia_promedio:.3f} ms  (objetivo ≤ 50ms)")
    print(f"  Latencia máxima                   : {m.latencia_max:.3f} ms")
    print(sep)

    # Guardar métricas en CSV para el póster
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    ruta_csv = os.path.join(OUTPUT_DIR, f"metricas_{ts}.csv")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(ruta_csv, "w") as f:
        f.write("metrica,valor\n")
        f.write(f"total,{m.total}\n")
        f.write(f"tp,{m.tp}\n")
        f.write(f"fp,{m.fp}\n")
        f.write(f"fn,{m.fn}\n")
        f.write(f"tn,{m.tn}\n")
        f.write(f"tpr,{m.tpr:.4f}\n")
        f.write(f"fpr,{m.fpr:.4f}\n")
        f.write(f"precision,{m.precision:.4f}\n")
        f.write(f"latencia_promedio_ms,{m.latencia_promedio:.4f}\n")
        f.write(f"latencia_max_ms,{m.latencia_max:.4f}\n")
    print(f"\n[✔] Métricas guardadas en: {ruta_csv}")


# ─────────────────────────────────────────────
# Experimento completo integrado
# ─────────────────────────────────────────────

def modo_experimento(args):
    """
    Ejecuta el experimento completo:
    1. Genera tráfico legítimo y spoofed
    2. Captura en vivo
    3. Analiza y reporta métricas
    """
    from scapy.all import wrpcap

    print("\n[EXPERIMENTO] Iniciando experimento controlado de IP Spoofing...")
    n_legitimos = args.count // 2
    n_spoofed   = args.count // 2

    paquetes_capturados = []
    ips_spoofed_usadas  = set()

    def capturar_cb(pkt):
        paquetes_capturados.append(pkt)

    # Captura en segundo plano
    from threading import Thread
    hilo_cap = Thread(
        target=lambda: sniff(
            iface=args.iface, filter="ip",
            count=args.count + 20,
            prn=capturar_cb, store=False
        )
    )
    hilo_cap.start()
    time.sleep(0.5)  # dejar que la captura inicie

    # Generar tráfico legítimo
    generar_trafico_legitimo(args.dst, n_legitimos, args.iface)
    # Generar tráfico spoofed
    ips_usadas = generar_trafico_spoofed(args.dst, n_spoofed, args.iface)
    ips_spoofed_usadas.update(ips_usadas)

    time.sleep(1)
    hilo_cap.join(timeout=5)

    # Guardar captura combinada
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    ruta_pcap = os.path.join(OUTPUT_DIR, f"experimento_{ts}.pcap")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if paquetes_capturados:
        wrpcap(ruta_pcap, paquetes_capturados)
        print(f"\n[✔] Captura guardada: {ruta_pcap} ({len(paquetes_capturados)} pkts)")
    else:
        print("[!] No se capturaron paquetes. Verificar interfaz.")
        return

    # Detectar anomalías
    resultados, metricas = detectar_anomalias_pcap(
        ruta_pcap,
        etiquetas_spoofed=ips_spoofed_usadas,
        verbose=False
    )

    imprimir_metricas(metricas)


# ─────────────────────────────────────────────
# Función principal
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="M3 — Detector de Anomalías IP (IF5000 Grupo 3)"
    )
    parser.add_argument("--modo", required=True,
                        choices=["generar", "detectar", "experimento"],
                        help="Modo de operación")
    parser.add_argument("--dst",   default="192.168.100.20",
                        help="IP destino para generación de paquetes")
    parser.add_argument("--iface", default=None,
                        help="Interfaz de red (si se omite, se elige automáticamente)")
    parser.add_argument("--count", type=int, default=100,
                        help="Número de paquetes (total, mitad legítimos / mitad spoofed)")
    parser.add_argument("--pcap",  default=None,
                        help="Archivo .pcap para modo detectar")
    parser.add_argument("--verbose", action="store_true",
                        help="Mostrar todos los paquetes, no solo anómalos")
    args = parser.parse_args()

    iface_final = seleccionar_interfaz(args.iface)

    if args.modo == "generar":
        generar_trafico_spoofed(args.dst, args.count, iface_final)
    elif args.modo == "detectar":
        if not args.pcap:
            print("[ERROR] --pcap requerido en modo detectar")
            sys.exit(1)
        resultados, metricas = detectar_anomalias_pcap(
            args.pcap, verbose=args.verbose
        )
        imprimir_metricas(metricas)
    elif args.modo == "experimento":
        modo_experimento(args)




if __name__ == "__main__":
    main()
