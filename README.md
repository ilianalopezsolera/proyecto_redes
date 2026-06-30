# IF5000 – Redes y Comunicación de Datos
## Proyecto Final – Grupo 3
### Análisis de la Capa de Red: Protocolo IPv4

**Universidad de Costa Rica – Sede del Sur**  
**Bachillerato en Informática Empresarial**  
**Profesor:** Mainor Cruz

---

# Descripción del proyecto

Este proyecto implementa un sistema para el análisis del **Protocolo IPv4 (Internet Protocol versión 4)** mediante el desarrollo de tres módulos en Python.

El sistema permite capturar tráfico de red, analizar manualmente la estructura de los datagramas IPv4 y detectar posibles anomalías relacionadas con **IP Spoofing**, utilizando el **TTL (Time To Live)** como indicador principal.

A diferencia de herramientas como Wireshark, el parser implementado analiza directamente los bytes del datagrama utilizando el módulo **struct** de Python, permitiendo comprender el funcionamiento interno del protocolo IPv4 según la **RFC 791**.

---

# Objetivos

El proyecto tiene como objetivo demostrar el funcionamiento del protocolo IPv4 mediante:

- Captura de tráfico IP real.
- Análisis manual de la cabecera de un datagrama IPv4.
- Interpretación de campos como TTL, fragmentación y checksum.
- Reensamblado de datagramas fragmentados.
- Detección de posibles anomalías asociadas a IP Spoofing.
- Comparación de los resultados obtenidos con Wireshark/tshark.

---

# Arquitectura del sistema

```text
                    ┌─────────────────────┐
                    │ Tráfico de Red IPv4 │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ M1 - Capturador     │
                    │ Captura paquetes    │
                    │ y genera .pcap      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ M2 - Parser IPv4    │
                    │ Analiza la cabecera │
                    │ del datagrama       │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ M3 - Detector       │
                    │ Detecta anomalías   │
                    │ (IP Spoofing)       │
                    └─────────────────────┘
```

---

# Módulos del sistema

| Módulo | Archivo | Descripción |
|--------|---------|-------------|
| **M1 – Capturador** | `módulos/m1_capturador.py` | Captura tráfico IPv4 desde una interfaz de red y genera archivos `.pcap`. |
| **M2 – Parser IPv4** | `módulos/m2_parser_ip.py` | Analiza manualmente la cabecera IPv4 leyendo directamente los bytes del datagrama mediante `struct`. |
| **M3 – Detector de anomalías** | `módulos/m3_detector_anomalias.py` | Detecta posibles casos de IP Spoofing mediante el análisis del TTL y otras características del tráfico. |

---

# Funcionalidades principales

El sistema implementa:

- Captura de tráfico IPv4 en tiempo real.
- Generación de archivos `.pcap`.
- Parser de bajo nivel utilizando `struct.unpack()`.
- Extracción de todos los campos de la cabecera IPv4.
- Verificación del Header Checksum.
- Detección de fragmentación.
- Reensamblado de datagramas fragmentados.
- Detección de posibles anomalías por TTL.
- Comparación de resultados con Wireshark.

---

# Requisitos

- Ubuntu Server 22.04 LTS (o superior)
- Python 3.10+
- Permisos **sudo** para captura de tráfico
- Conexión de red para pruebas en vivo

---

# Dependencias

El proyecto utiliza las siguientes dependencias:

- Python 3
- Scapy 2.5.0
- Pandas
- Matplotlib
- Tabulate
- tshark
- wireshark-common

Todas las dependencias pueden instalarse automáticamente mediante el script incluido.

---

# Instalación

## 1. Clonar el repositorio

```bash
git clone <URL_DEL_REPOSITORIO>
cd IP_PROJECT
```

## 2. Instalar dependencias

```bash
sudo bash install.sh
```

## 3. Activar el entorno virtual

```bash
source .venv/bin/activate
```

---

# Estructura del proyecto

```text
IP_PROJECT
│
├── módulos
│   ├── app.py
│   ├── m1_capturador.py
│   ├── m2_parser_ip.py
│   └── m3_detector_anomalias.py
│
├── pcap_samples
│   ├── captura_real.pcap
│   ├── experimento_mixto.pcap
│   ├── trafico_normal.pcap
│   ├── trafico_spoofed.pcap
│   └── ips_spoofed.txt
│
├── templates
│
├── tests
│   ├── generar_pcap_muestra.py
│   └── test_m2_parser.py
│
├── install.sh
├── .gitignore
└── README.md
```

---

# Archivos PCAP incluidos

El repositorio incluye capturas de muestra para facilitar la reproducción de las pruebas.

| Archivo | Descripción |
|----------|-------------|
| `captura_real.pcap` | Captura de tráfico IPv4 real. |
| `trafico_normal.pcap` | Tráfico normal sin anomalías. |
| `trafico_spoofed.pcap` | Tráfico generado con IP Spoofing. |
| `experimento_mixto.pcap` | Mezcla de tráfico normal y tráfico anómalo. |

---

# Ejecución del sistema

## Módulo 1 – Captura de tráfico

Captura paquetes IPv4 desde una interfaz de red y genera un archivo `.pcap`.

```bash
sudo python3 módulos/m1_capturador.py
```

---

## Módulo 2 – Parser IPv4

Analiza una captura existente e interpreta manualmente la cabecera IPv4.

```bash
python3 módulos/m2_parser_ip.py --pcap pcap_samples/trafico_normal.pcap --resumen
```

---

## Módulo 3 – Detector de anomalías

Analiza una captura y detecta posibles paquetes sospechosos.

```bash
python3 módulos/m3_detector_anomalias.py --modo detectar --pcap pcap_samples/experimento_mixto.pcap
```

---

# Reproducción del experimento

Para reproducir completamente el experimento realizado durante el proyecto:

1. Capturar tráfico utilizando el módulo M1.
2. Generar el archivo `.pcap`.
3. Analizar la captura mediante el parser IPv4 (M2).
4. Ejecutar el detector de anomalías (M3).
5. Comparar los resultados obtenidos con Wireshark o tshark.

Los archivos de ejemplo incluidos permiten realizar todas las pruebas sin necesidad de capturar tráfico nuevo.

---

# Funcionamiento del sistema

## M1 – Capturador

Captura tráfico IPv4 desde una interfaz de red y almacena los paquetes en formato `.pcap`.

---

## M2 – Parser IPv4

El parser implementa un análisis de bajo nivel utilizando `struct.unpack()` para interpretar directamente los bytes del datagrama IPv4.

Extrae los siguientes campos:

- Versión
- Longitud de cabecera (IHL)
- Longitud total
- Identificación
- Flags
- Fragment Offset
- TTL
- Protocolo
- Header Checksum
- Dirección IP origen
- Dirección IP destino

Además:

- Verifica el checksum.
- Detecta fragmentación.
- Simula el reensamblado de fragmentos.

---

## M3 – Detector de anomalías

Este módulo analiza el TTL de los paquetes capturados para detectar posibles casos de **IP Spoofing**.

Se comparan los TTL observados con los valores iniciales típicos de los principales sistemas operativos:

| Sistema Operativo | TTL inicial |
|-------------------|------------:|
| Linux / macOS | 64 |
| Windows | 128 |
| Cisco IOS | 255 |

Cuando un paquete presenta un TTL inconsistente con estos valores, se reporta como una posible anomalía.

---

# Validación con Wireshark

Los resultados obtenidos por el parser pueden compararse con Wireshark o tshark para verificar la correcta interpretación de la cabecera IPv4.

Ejemplo:

```bash
tshark -r pcap_samples/trafico_normal.pcap -V
```

La comparación permite validar campos como:

- Direcciones IP
- TTL
- Checksum
- Protocolo
- Fragmentación

---

# Resultados esperados

Al ejecutar correctamente el proyecto, el usuario podrá:

- Capturar tráfico IPv4.
- Generar archivos `.pcap`.
- Analizar manualmente la cabecera IPv4.
- Identificar fragmentación y reensamblado.
- Detectar posibles anomalías mediante el TTL.
- Comparar los resultados con Wireshark.

---

# RFC de referencia

- RFC 791 – Internet Protocol (IPv4)
- RFC 1122 – Requirements for Internet Hosts

---

# Integrantes

- Meylin Iliana López Solera
- Yesly Daniela Figueroa Arauz
- Yileidy Rivera Granados

---

# Asistencia de IA

Durante el desarrollo de este proyecto se utilizaron herramientas de Inteligencia Artificial Generativa como apoyo para:

- Estructurar la propuesta inicial de la solución.
- Generar una primera versión del código base de los módulos M1, M2 y M3.
- Resolver dudas relacionadas con Python, Scapy y el protocolo IPv4.
- Apoyar la elaboración de la documentación del proyecto.

---
