#!/usr/bin/env python3
"""
=============================================================================
app.py — Servidor Web Flask para IF5000 Grupo 3
=============================================================================
Expone los módulos M1, M2 y M3 mediante una API REST simple.
Correr en la VM: sudo python3 módulos/app.py
Acceder desde tu PC: http://IP_DE_LA_VM:5000
=============================================================================
"""

import os
import sys
import json
import threading
import datetime
import subprocess

from flask import Flask, render_template, jsonify, request

# Agregar módulos al path
sys.path.insert(0, os.path.dirname(__file__))

from m2_parser_ip import parsear_datagrama, imprimir_resumen, TTL_OS
from m3_detector_anomalias import ttl_es_anomalo, MetricasDeteccion

app = Flask(__name__, template_folder="../templates")

# ── Estado global compartido ──────────────────────────────
estado = {
    "capturando": False,
    "paquetes":   [],       # lista de dicts con info de cada paquete
    "metricas":   {},
    "log":        [],
}
lock = threading.Lock()


def agregar_log(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    with lock:
        estado["log"].append(f"[{ts}] {msg}")
        if len(estado["log"]) > 200:
            estado["log"].pop(0)


# ── Rutas principales ─────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/estado")
def api_estado():
    with lock:
        return jsonify({
            "capturando": estado["capturando"],
            "total":      len(estado["paquetes"]),
            "paquetes":   estado["paquetes"][-50:],   # últimos 50
            "metricas":   estado["metricas"],
            "log":        estado["log"][-30:],
        })


@app.route("/api/capturar", methods=["POST"])
def api_capturar():
    """Inicia captura M1 en segundo plano."""
    if estado["capturando"]:
        return jsonify({"error": "Ya hay una captura en curso"}), 400

    data  = request.json or {}
    iface = data.get("iface", "enp0s8")
    count = int(data.get("count", 50))

    def hilo_captura():
        from scapy.all import sniff, IP, raw
        with lock:
            estado["capturando"] = True
            estado["paquetes"]   = []
        agregar_log(f"Iniciando captura en {iface} — {count} paquetes")

        def procesar(pkt):
            if IP not in pkt:
                return
            from scapy.all import IP as ScapyIP
            ip = pkt[ScapyIP]

            # Parseo a bajo nivel con M2
            raw_bytes = raw(ip)
            d = parsear_datagrama(raw_bytes, 0)
            if not d:
                return

            anomalo, razon = ttl_es_anomalo(ip.ttl)
            proto_nombre = {1:"ICMP", 6:"TCP", 17:"UDP"}.get(ip.proto, f"PROTO-{ip.proto}")

            pkt_info = {
                "src":      ip.src,
                "dst":      ip.dst,
                "ttl":      ip.ttl,
                "proto":    proto_nombre,
                "len":      ip.len,
                "id":       hex(ip.id),
                "df":       int(d.flag_df),
                "mf":       int(d.flag_mf),
                "frag":     d.frag_offset,
                "checksum": hex(d.checksum_hdr),
                "ck_ok":    d.checksum_ok,
                "anomalo":  anomalo,
                "razon":    razon,
                "os_est":   TTL_OS.get(ip.ttl, "no estándar"),
                "ts":       datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
            }
            with lock:
                estado["paquetes"].append(pkt_info)
            if anomalo:
                agregar_log(f"⚠ ANOMALO {ip.src} TTL={ip.ttl} — {razon[:60]}")

        try:
            sniff(iface=iface, filter="ip", count=count, prn=procesar, store=False)
        except Exception as e:
            agregar_log(f"Error en captura: {e}")

        # Calcular métricas al terminar
        with lock:
            pkts = estado["paquetes"]
            total    = len(pkts)
            anomalos = sum(1 for p in pkts if p["anomalo"])
            normales = total - anomalos
            protos   = {}
            ttls     = {}
            for p in pkts:
                protos[p["proto"]] = protos.get(p["proto"], 0) + 1
                ttls[str(p["ttl"])] = ttls.get(str(p["ttl"]), 0) + 1

            estado["metricas"] = {
                "total":    total,
                "anomalos": anomalos,
                "normales": normales,
                "protos":   protos,
                "ttls":     ttls,
            }
            estado["capturando"] = False
        agregar_log(f"Captura finalizada — {total} paquetes, {anomalos} anómalos")

    threading.Thread(target=hilo_captura, daemon=True).start()
    return jsonify({"ok": True, "msg": f"Captura iniciada en {iface}"})


@app.route("/api/generar_spoofed", methods=["POST"])
def api_generar_spoofed():
    """Genera tráfico spoofed desde M3 en segundo plano."""
    data  = request.json or {}
    dst   = data.get("dst",   "192.168.100.20")
    count = int(data.get("count", 20))
    iface = data.get("iface", "enp0s8")

    def hilo_spoofed():
        from m3_detector_anomalias import generar_trafico_spoofed
        agregar_log(f"Generando {count} paquetes spoofed → {dst}")
        try:
            generar_trafico_spoofed(dst, count, iface, verbose=False)
            agregar_log(f"✔ {count} paquetes spoofed enviados a {dst}")
        except Exception as e:
            agregar_log(f"Error generando spoofed: {e}")

    threading.Thread(target=hilo_spoofed, daemon=True).start()
    return jsonify({"ok": True, "msg": f"Generando {count} paquetes spoofed → {dst}"})


@app.route("/api/analizar_pcap", methods=["POST"])
def api_analizar_pcap():
    """Analiza un .pcap con M2 y M3."""
    data     = request.json or {}
    ruta     = data.get("ruta", "pcap_samples/experimento_mixto.pcap")

    if not os.path.exists(ruta):
        return jsonify({"error": f"Archivo no encontrado: {ruta}"}), 404

    from scapy.all import rdpcap, IP as ScapyIP, raw
    from m3_detector_anomalias import MetricasDeteccion

    pkts     = rdpcap(ruta)
    m        = MetricasDeteccion()
    resultado = []

    for i, pkt in enumerate(pkts):
        if ScapyIP not in pkt:
            continue
        ip        = pkt[ScapyIP]
        raw_bytes = raw(ip)
        d         = parsear_datagrama(raw_bytes, i)
        if not d:
            continue
        anomalo, razon = ttl_es_anomalo(ip.ttl)
        if anomalo:
            m.fp += 1   # sin etiquetas reales, todo anómalo cuenta como FP aproximado
        else:
            m.tn += 1
        resultado.append({
            "src": ip.src, "dst": ip.dst,
            "ttl": ip.ttl, "anomalo": anomalo,
            "ck_ok": d.checksum_ok,
            "frag": d.es_fragmento,
        })

    agregar_log(f"Análisis de {ruta}: {len(resultado)} paquetes IP procesados")
    return jsonify({"paquetes": resultado, "total": len(resultado)})


@app.route("/api/limpiar", methods=["POST"])
def api_limpiar():
    with lock:
        estado["paquetes"] = []
        estado["metricas"] = {}
        estado["log"]      = []
    return jsonify({"ok": True})


# ── Arranque ──────────────────────────────────────────────
if __name__ == "__main__":
    ip_vm = subprocess.getoutput("hostname -I").split()[0]
    print("=" * 55)
    print(" IF5000 — Grupo 3 — Servidor Web")
    print(f" Abrir en tu PC: http://{ip_vm}:5000")
    print("=" * 55)
    app.run(host="0.0.0.0", port=5000, debug=False)
