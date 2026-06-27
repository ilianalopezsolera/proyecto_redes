#!/usr/bin/env bash
# =============================================================================
# install.sh — Instalación del entorno para el Proyecto IF5000 Grupo 3
# Probado en Ubuntu Server 22.04 LTS
# Ejecutar como: sudo bash install.sh
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================="
echo " IF5000 — Proyecto Capa de Red: Protocolo IP"
echo " Script de instalación — Ubuntu Server"
echo "============================================="

# 1. Actualizar repositorios
apt-get update -y

# 2. Instalar dependencias del sistema
apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    tcpdump \
    tshark \
    wireshark-common \
    net-tools \
    iproute2 \
    iputils-ping \
    git

# 3. Crear entorno virtual Python
python3 -m venv "$SCRIPT_DIR/.venv"
source "$SCRIPT_DIR/.venv/bin/activate"

# 4. Instalar librerías Python
pip install --upgrade pip
pip install scapy==2.5.0 matplotlib pandas tabulate

# 5. Permisos para captura sin root (opcional, root recomendado para demo)
setcap cap_net_raw,cap_net_admin=eip $(which python3) 2>/dev/null || true
chmod +x "$SCRIPT_DIR"/módulos/*.py "$SCRIPT_DIR"/src/*.py 2>/dev/null || true

echo ""
echo "✔  Instalación completa."
echo "   Active el entorno con:  source $SCRIPT_DIR/.venv/bin/activate"
echo "   Luego ejecute:          sudo python3 módulos/m1_capturador.py"
