# IF5000 — Redes y Comunicación de Datos
## Grupo 3 — Capa de Red: Protocolo IP
**Universidad de Costa Rica · Sede del Sur · Bach. Informática Empresarial**  
Profesor: Mainor Cruz | Presentación: 23 de junio de 2026

---

## Descripción del sistema

Sistema de análisis de la **Capa de Red (Protocolo IP)** que implementa:

| Módulo | Archivo | Función |
|--------|---------|---------|
| **M1 — Capturador** | `src/m1_capturador.py` | Captura tráfico IP real y genera `.pcap` |
| **M2 — Parser IP** | `src/m2_parser_ip.py` | Parsea datagramas IPv4 con `struct` (RFC 791) |
| **M3 — Detector** | `src/m3_detector_anomalias.py` | Detecta IP Spoofing por TTL anómalo |

El parseo del datagrama IP opera **directamente sobre bytes crudos** con `struct.unpack`, sin delegar en librerías de alto nivel, cumpliendo el Componente 2 del enunciado.

---

## Requisitos

- Ubuntu Server 22.04 LTS (o 20.04)
- Python 3.10+
- Scapy 2.5.0, matplotlib, pandas, tabulate
- `tshark` / `wireshark-common` (validación)
- Ejecutar con `sudo` para captura en vivo y sockets RAW

---

## Instalación

```bash
# 1. Clonar el repositorio
git clone https://github.com/[usuario]/if5000-grupo3-ip.git
cd if5000-grupo3-ip

# 2. Instalar dependencias (requiere sudo)
sudo bash install.sh

# 3. Activar entorno virtual
source .venv/bin/activate

# 4. Generar capturas de muestra (no requiere red)
python3 tests/generar_pcap_muestra.py
```

---

## Guía rápida para Ubuntu Server y máquinas virtuales

### 1. Preparar cada máquina virtual
En cada VM, clonar el proyecto y crear el entorno virtual:

```bash
git clone <url-del-repo>
cd ip_project
sudo apt update
sudo apt install -y python3 python3-pip python3-venv tcpdump tshark wireshark-common
python3 -m venv .venv
source .venv/bin/activate
pip install scapy==2.5.0 matplotlib pandas tabulate
```

### 2. Máquina cliente (192.168.100.10)
Esta VM genera tráfico y captura paquetes:

```bash
sudo python3 módulos/m1_capturador.py --iface ens33 --count 100 --output cliente_capture.pcap
```

Si quieren simular el ataque de IP spoofing:

```bash
sudo python3 módulos/m3_detector_anomalias.py --modo generar --dst 192.168.100.20 --iface ens33 --count 50
```

### 3. Máquina servidor (192.168.100.20)
Esta VM recibe el tráfico y lo analiza:

```bash
sudo python3 módulos/m2_parser_ip.py --pcap cliente_capture.pcap --resumen
```

Y para detectar anomalías:

```bash
python3 módulos/m3_detector_anomalias.py --modo detectar --pcap cliente_capture.pcap --verbose
```

> Si la interfaz de red no es ens33, reemplázala por la que aparezca en la VM con: `ip a`.

---

## Uso — Reproducción de experimentos

### M1 — Capturar tráfico en vivo
```bash
# Capturar 100 paquetes IP en eth0
sudo python3 src/m1_capturador.py --iface eth0 --count 100 --output mi_captura.pcap

# Solo tráfico ICMP
sudo python3 src/m1_capturador.py --filter icmp --count 50 --output icmp.pcap
```

### M2 — Parsear datagramas IP (bajo nivel)
```bash
# Parsear una captura existente (campo a campo, sin librerías de alto nivel)
sudo python3 src/m2_parser_ip.py --pcap pcap_samples/trafico_normal.pcap --resumen

# Mostrar solo fragmentos
sudo python3 src/m2_parser_ip.py --pcap pcap_samples/trafico_normal.pcap --solo-frags

# Captura en vivo + parseo inmediato
sudo python3 src/m2_parser_ip.py --live --iface eth0 --count 30 --resumen
```

### M3 — Detectar anomalías / IP Spoofing
```bash
# Detectar anomalías en captura de muestra
python3 src/m3_detector_anomalias.py --modo detectar \
    --pcap pcap_samples/experimento_mixto.pcap --verbose

# Generar tráfico spoofed hacia VM destino (requiere sudo + red)
sudo python3 src/m3_detector_anomalias.py --modo generar \
    --dst 192.168.100.10 --iface eth0 --count 50

# Experimento completo integrado (genera + captura + analiza + métricas)
sudo python3 src/m3_detector_anomalias.py --modo experimento \
    --iface eth0 --dst 192.168.100.10 --count 100
```

### Tests automatizados (sin red)
```bash
python3 tests/test_m2_parser.py
```

---

## Validación con Wireshark / tshark

Comparar nuestra salida contra tshark para verificar correctitud:

```bash
# Ver campos IP que tshark extrae de la misma captura
tshark -r pcap_samples/trafico_normal.pcap -V \
    | grep -E "Source|Destination|Time to live|Header checksum|Flags"

# Distribución de TTL (comparar con resumen de M2)
tshark -r pcap_samples/experimento_mixto.pcap \
    -T fields -e ip.ttl | sort -n | uniq -c

# Detectar fragmentación
tshark -r pcap_samples/trafico_normal.pcap \
    -Y "ip.flags.mf == 1 or ip.frag_offset > 0"
```

---

## Estructura del repositorio

```
if5000-grupo3-ip/
├── README.md
├── install.sh                  ← Instalación automática (Ubuntu Server)
├── módulos/
│   ├── m1_capturador.py        ← Componente 1: captura tráfico real
│   ├── m2_parser_ip.py         ← Componente 2: parser bajo nivel (struct)
│   └── m3_detector_anomalias.py ← Componente 3: detección IP Spoofing
├── tests/
│   ├── test_m2_parser.py       ← Suite de tests automatizados
│   └── generar_pcap_muestra.py ← Genera .pcap reproducibles
├── pcap_samples/               ← Capturas de muestra (generadas con el script)
│   ├── trafico_normal.pcap
│   ├── trafico_spoofed.pcap
│   └── experimento_mixto.pcap
└── docs/
    └── (diagramas y figuras del póster)
```

---

## Anomalía analizada: IP Spoofing por TTL anómalo

El detector (M3) identifica paquetes sospechosos comparando su TTL contra los valores esperados según el sistema operativo de origen:

| OS | TTL inicial | Rango legítimo (≤5 hops) |
|----|-------------|--------------------------|
| Linux / macOS | 64 | 59 – 64 |
| Windows | 128 | 123 – 128 |
| Cisco IOS | 255 | 250 – 255 |

Un paquete cuyo TTL **no cae en ningún rango** se marca como anómalo (posible IP Spoofing).

**Métricas objetivo:**
- TPR ≥ 90% · FPR ≤ 5% · Latencia ≤ 50 ms

---

## RFC de referencia

- RFC 791 — Internet Protocol (IPv4): https://www.rfc-editor.org/rfc/rfc791  
- RFC 1122 — Requirements for Internet Hosts: https://www.rfc-editor.org/rfc/rfc1122

---

## Asistencia de IA

Este proyecto utilizó Claude (Anthropic) como asistente para:
- Estructurar la propuesta de solución (E1)
- Generar la base del código de los módulos M1, M2 y M3
- El equipo revisó, adaptó y extendió el código resultante

Todo el código fue verificado y probado por los integrantes del grupo.
