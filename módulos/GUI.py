#!/usr/bin/env python3
"""
=============================================================================
Interfaz Gráfica — Analizador de Protocolo IP
IF5000 — Redes y Comunicación de Datos | Grupo 3 — Protocolo IP
=============================================================================
Ejecutar: python3 módulos/gui_ip_analyzer.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog
import threading
import os
import sys
import datetime
import json
import subprocess

# Importar módulos existentes
from m1_capturador import capturar_o_fallback
from m2_parser_ip import parsear_datagrama, DatagramaIP
from m3_detector_anomalias import detectar_anomalias_pcap, MetricasDeteccion

class IPAnalyzerGUI:
    """Interfaz gráfica principal del analizador IP."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("IF5000 — Analizador de Protocolo IP (Grupo 3)")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f0f0f0')
        
        # Variables de estado
        self.capturando = False
        self.analizando = False
        self.detectando = False
        self.paquetes_capturados = []
        self.resultados_analisis = []
        self.metricas = None
        
        # Crear interfaz
        self._crear_menu()
        self._crear_widgets()
        self._crear_barra_estado()
        
        # Redirigir salida
        self._redirigir_consola()
        
        # Mensaje de bienvenida
        self._log("=" * 70, "header")
        self._log("🔍 IF5000 — Analizador de Protocolo IP", "header")
        self._log(f"📅 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self._log("=" * 70, "header")
        self._log("Seleccione una acción en el panel superior")
    
    def _crear_menu(self):
        """Barra de menú."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Archivo
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Archivo", menu=file_menu)
        file_menu.add_command(label="Abrir .pcap", command=self._abrir_pcap)
        file_menu.add_command(label="Guardar Reporte", command=self._guardar_reporte)
        file_menu.add_separator()
        file_menu.add_command(label="Salir", command=self.root.quit)
        
        # Herramientas
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Herramientas", menu=tools_menu)
        tools_menu.add_command(label="Generar Tráfico Spoofed", command=self._generar_spoofing)
        tools_menu.add_command(label="Generar Tráfico Legítimo", command=self._generar_legitimo)
        tools_menu.add_separator()
        tools_menu.add_command(label="Validar con tshark", command=self._validar_tshark)
        tools_menu.add_command(label="Limpiar Consola", command=self._limpiar_consola)
        
        # Ayuda
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ayuda", menu=help_menu)
        help_menu.add_command(label="Acerca de", command=self._mostrar_acerca)
        help_menu.add_command(label="RFC 791", command=self._mostrar_rfc)
    
    def _crear_widgets(self):
        """Crea todos los widgets."""
        # Paneles
        panel_principal = ttk.Frame(self.root, padding="10")
        panel_principal.pack(fill=tk.BOTH, expand=True)
        
        # Panel superior - tarjetas
        panel_superior = ttk.Frame(panel_principal)
        panel_superior.pack(fill=tk.X, pady=(0, 10))
        
        # Tarjeta 1: Captura
        self._crear_tarjeta_captura(panel_superior)
        
        # Tarjeta 2: Análisis
        self._crear_tarjeta_analisis(panel_superior)
        
        # Tarjeta 3: Detección
        self._crear_tarjeta_deteccion(panel_superior)
        
        # Panel central - consola
        panel_consola = ttk.LabelFrame(panel_principal, text="📋 Consola", padding="5")
        panel_consola.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.consola = scrolledtext.ScrolledText(
            panel_consola,
            height=15,
            font=("Consolas", 10),
            wrap=tk.WORD,
            bg="#1e1e1e",
            fg="#d4d4d4"
        )
        self.consola.pack(fill=tk.BOTH, expand=True)
        
        # Tags de color
        self.consola.tag_config("info", foreground="#4ec9b0")
        self.consola.tag_config("warning", foreground="#dcdcaa")
        self.consola.tag_config("error", foreground="#f44747")
        self.consola.tag_config("success", foreground="#6a9955")
        self.consola.tag_config("header", foreground="#569cd6", font=("Consolas", 11, "bold"))
        
        # Panel inferior - métricas
        self._crear_panel_metricas(panel_principal)
        
        # Botones inferiores
        panel_botones = ttk.Frame(panel_principal)
        panel_botones.pack(fill=tk.X, pady=5)
        
        ttk.Button(panel_botones, text="📸 Capturar Pantalla", 
                  command=self._capturar_pantalla).pack(side=tk.LEFT, padx=5)
        ttk.Button(panel_botones, text="📁 Guardar Reporte", 
                  command=self._guardar_reporte).pack(side=tk.LEFT, padx=5)
        ttk.Button(panel_botones, text="🗑️ Limpiar Consola", 
                  command=self._limpiar_consola).pack(side=tk.LEFT, padx=5)
        ttk.Button(panel_botones, text="❌ Salir", 
                  command=self.root.quit).pack(side=tk.RIGHT, padx=5)
    
    def _crear_tarjeta_captura(self, parent):
        """Tarjeta de captura."""
        frame = ttk.LabelFrame(parent, text="📡 Capturar Tráfico", padding="10")
        frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        ttk.Label(frame, text="Interfaz:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(frame, textvariable=self.iface_var, width=30)
        self.iface_combo.grid(row=0, column=1, sticky=tk.W, pady=2)

        try:
            from scapy.all import get_if_list
            ifaces = get_if_list()
            interfaces = [i for i in ifaces if 'Loopback' not in i]
            if not interfaces:
                interfaces = ifaces
            self.iface_combo['values'] = interfaces
            if interfaces:
                self.iface_var.set(interfaces[0])
        except Exception:
            self.iface_combo['values'] = ['Ethernet', 'Wi-Fi']
            self.iface_var.set('Ethernet')

        ttk.Label(frame, text="Cantidad:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.count_var = tk.IntVar(value=50)
        ttk.Spinbox(frame, from_=1, to=1000, textvariable=self.count_var, width=10).grid(row=1, column=1, sticky=tk.W, pady=2)

        ttk.Label(frame, text="Filtro:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.filter_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.filter_var, width=30).grid(row=2, column=1, sticky=tk.W, pady=2)

        self.btn_capturar = ttk.Button(frame, text="▶ Iniciar", command=self._iniciar_captura)
        self.btn_capturar.grid(row=3, column=0, pady=10)

        self.btn_detener = ttk.Button(frame, text="⏹ Detener", command=self._detener_captura, state=tk.DISABLED)
        self.btn_detener.grid(row=3, column=1, pady=10)




    def _crear_tarjeta_analisis(self, parent):
        """Tarjeta de análisis."""
        frame = ttk.LabelFrame(parent, text="📊 Analizar .pcap", padding="10")
        frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        ttk.Label(frame, text="Archivo:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.pcap_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.pcap_var, width=25).grid(row=0, column=1, sticky=tk.W, pady=2)
        ttk.Button(frame, text="📂", width=3, command=self._seleccionar_pcap).grid(row=0, column=2, padx=5)
        
        self.verbose_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Mostrar detalles", variable=self.verbose_var).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        self.resumen_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Mostrar resumen", variable=self.resumen_var).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        self.btn_analizar = ttk.Button(frame, text="🔍 Analizar", command=self._analizar_pcap)
        self.btn_analizar.grid(row=3, column=0, columnspan=2, pady=10, sticky=(tk.W, tk.E))
    
    def _crear_tarjeta_deteccion(self, parent):
        """Tarjeta de detección."""
        frame = ttk.LabelFrame(parent, text="🚨 Detectar Anomalías", padding="10")
        frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        ttk.Label(frame, text="Archivo:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.detect_pcap_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.detect_pcap_var, width=25).grid(row=0, column=1, sticky=tk.W, pady=2)
        ttk.Button(frame, text="📂", width=3, command=self._seleccionar_detect_pcap).grid(row=0, column=2, padx=5)
        
        ttk.Label(frame, text="IPs Spoofed:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.spoofed_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.spoofed_var, width=25).grid(row=1, column=1, sticky=tk.W, pady=2)
        ttk.Button(frame, text="📂", width=3, command=self._seleccionar_spoofed).grid(row=1, column=2, padx=5)
        
        self.btn_detectar = ttk.Button(frame, text="🚨 Detectar", command=self._detectar_anomalias)
        self.btn_detectar.grid(row=2, column=0, columnspan=2, pady=10, sticky=(tk.W, tk.E))
    
    def _crear_panel_metricas(self, parent):
        """Panel de métricas."""
        frame = ttk.LabelFrame(parent, text="📊 Métricas de Detección", padding="5")
        frame.pack(fill=tk.X, pady=(0, 5))
        
        metricas_info = [
            ("TPR (Recall)", "0%", "green"),
            ("FPR", "0%", "orange"),
            ("Precisión", "0%", "blue"),
            ("TP", "0", "darkgreen"),
            ("FP", "0", "red"),
            ("FN", "0", "darkred"),
            ("TN", "0", "darkblue"),
            ("Latencia", "0ms", "purple")
        ]
        
        self.metricas_labels = {}
        for i, (label, valor, color) in enumerate(metricas_info):
            f = ttk.Frame(frame)
            f.grid(row=0, column=i, padx=15, pady=5)
            ttk.Label(f, text=f"{label}:").pack(side=tk.LEFT)
            lbl = ttk.Label(f, text=valor, font=("Segoe UI", 10, "bold"), foreground=color)
            lbl.pack(side=tk.LEFT, padx=(5, 0))
            self.metricas_labels[label] = lbl
    
    def _crear_barra_estado(self):
        """Barra de estado."""
        self.status_var = tk.StringVar(value="✅ Listo")
        status = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=(5, 2))
        status.pack(fill=tk.X, side=tk.BOTTOM)
    
    def _redirigir_consola(self):
        """Redirige print() a la consola."""
        import builtins
        original_print = builtins.print
        
        def gui_print(*args, **kwargs):
            text = " ".join(str(arg) for arg in args)
            tag = "info"
            if "ERROR" in text or "Error" in text:
                tag = "error"
            elif "✔" in text or "completado" in text or "éxito" in text:
                tag = "success"
            elif "⚠" in text or "anómalo" in text or "spoofed" in text:
                tag = "warning"
            elif "=" * 10 in text:
                tag = "header"
            self._log(text, tag)
        
        builtins.print = gui_print
    
    def _log(self, mensaje, tag="info"):
        """Agrega mensaje a la consola."""
        self.consola.insert(tk.END, mensaje + "\n", tag)
        self.consola.see(tk.END)
        self.root.update_idletasks()
    
    def _set_status(self, mensaje):
        """Actualiza barra de estado."""
        self.status_var.set(f"• {mensaje}")
    
    # ── Funciones de captura ──
    
    def _iniciar_captura(self):
        if self.capturando:
            return
        
        self.capturando = True
        self.btn_capturar.config(state=tk.DISABLED)
        self.btn_detener.config(state=tk.NORMAL)
        self._set_status("Capturando tráfico...")
        self._log("▶ Iniciando captura...", "header")
        
        threading.Thread(target=self._capturar_thread, daemon=True).start()
    
    def _capturar_thread(self):
        try:
            from scapy.all import sniff, wrpcap
            from scapy.all import IP
            
            iface = self.iface_var.get()
            count = self.count_var.get()
            filtro = self.filter_var.get()
            
            self.paquetes_capturados = []
            
            def callback(pkt):
                if IP in pkt:
                    self.paquetes_capturados.append(pkt)
                    self._log(f"  📦 Paquete #{len(self.paquetes_capturados)}: {pkt[IP].src} → {pkt[IP].dst}", "info")
            
            sniff(iface=iface, filter=filtro, count=count, prn=callback)
            
            self._log(f"✅ Capturados {len(self.paquetes_capturados)} paquetes", "success")
            self._set_status(f"Capturados {len(self.paquetes_capturados)} paquetes")
            
            # Guardar si hay paquetes
            if self.paquetes_capturados:
                if messagebox.askyesno("Guardar", "¿Guardar la captura en .pcap?"):
                    self._guardar_captura()
            
        except Exception as e:
            self._log(f"❌ Error: {e}", "error")
            self._set_status("Error en captura")
        finally:
            self.capturando = False
            self.btn_capturar.config(state=tk.NORMAL)
            self.btn_detener.config(state=tk.DISABLED)
    
    def _detener_captura(self):
        self.capturando = False
        self._log("⏹ Captura detenida", "warning")
        self._set_status("Captura detenida")
    
    def _guardar_captura(self):
        if not self.paquetes_capturados:
            return
        
        archivo = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap")]
        )
        if archivo:
            from scapy.all import wrpcap
            wrpcap(archivo, self.paquetes_capturados)
            self._log(f"✅ Guardado: {archivo}", "success")
    
    # ── Funciones de análisis ──
    
    def _seleccionar_pcap(self):
        archivo = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
        if archivo:
            self.pcap_var.set(archivo)
    
    def _analizar_pcap(self):
        if self.analizando:
            return
        
        archivo = self.pcap_var.get()
        if not archivo or not os.path.exists(archivo):
            messagebox.showerror("Error", "Seleccione un archivo .pcap válido")
            return
        
        self.analizando = True
        self.btn_analizar.config(state=tk.DISABLED)
        self._set_status("Analizando...")
        self._log(f"📊 Analizando: {os.path.basename(archivo)}", "header")
        
        threading.Thread(target=self._analizar_thread, args=(archivo,), daemon=True).start()
    
    def _analizar_thread(self, archivo):
        try:
            from scapy.all import rdpcap, IP as ScapyIP, raw
            from m2_parser_ip import parsear_datagrama, imprimir_datagrama, imprimir_resumen
            
            pkts = rdpcap(archivo)
            self.resultados_analisis = []
            
            for i, pkt in enumerate(pkts):
                if ScapyIP in pkt:
                    raw_bytes = raw(pkt[ScapyIP])
                    d = parsear_datagrama(raw_bytes, i+1)
                    if d:
                        self.resultados_analisis.append(d)
            
            self._log(f"📊 {len(self.resultados_analisis)} datagramas IP parseados", "info")
            
            if self.verbose_var.get():
                for d in self.resultados_analisis[:15]:
                    imprimir_datagrama(d)
            
            if self.resumen_var.get():
                self._mostrar_resumen()
            
            self._log("✅ Análisis completado", "success")
            self._set_status(f"Analizados {len(self.resultados_analisis)} paquetes")
            
        except Exception as e:
            self._log(f"❌ Error: {e}", "error")
            self._set_status("Error en análisis")
        finally:
            self.analizando = False
            self.btn_analizar.config(state=tk.NORMAL)
    
    def _mostrar_resumen(self):
        datos = self.resultados_analisis
        if not datos:
            return
        
        total = len(datos)
        ck_ok = sum(1 for d in datos if d.checksum_ok)
        frags = sum(1 for d in datos if d.es_fragmento)
        
        self._log("=" * 70, "header")
        self._log(f"📊 RESUMEN — {total} datagramas", "header")
        self._log("=" * 70, "header")
        self._log(f"  Checksum válido: {ck_ok}/{total} ({100*ck_ok//total}%)")
        self._log(f"  Fragmentados: {frags}")
        
        # Distribución de protocolos
        protos = {}
        for d in datos:
            from m2_parser_ip import PROTO_NOMBRES
            pn = PROTO_NOMBRES.get(d.protocolo, f"PROTO-{d.protocolo}")
            protos[pn] = protos.get(pn, 0) + 1
        
        self._log("  Protocolos:")
        for proto, cnt in sorted(protos.items(), key=lambda x: -x[1]):
            self._log(f"    {proto:<8} {cnt:>5}")
        
        # Distribución de TTL
        ttls = {}
        for d in datos:
            ttls[d.ttl] = ttls.get(d.ttl, 0) + 1
        
        self._log("  Distribución TTL:")
        for ttl, cnt in sorted(ttls.items()):
            from m2_parser_ip import TTL_OS
            os_h = TTL_OS.get(ttl, "no estándar")
            self._log(f"    TTL={ttl:<3}  {cnt:>5} paquetes  ({os_h})")
        
        self._log("=" * 70, "header")
    
    # ── Funciones de detección ──
    
    def _seleccionar_detect_pcap(self):
        archivo = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
        if archivo:
            self.detect_pcap_var.set(archivo)
    
    def _seleccionar_spoofed(self):
        archivo = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if archivo:
            self.spoofed_var.set(archivo)
    
    def _detectar_anomalias(self):
        if self.detectando:
            return
        
        archivo = self.detect_pcap_var.get()
        if not archivo or not os.path.exists(archivo):
            messagebox.showerror("Error", "Seleccione un archivo .pcap válido")
            return
        
        self.detectando = True
        self.btn_detectar.config(state=tk.DISABLED)
        self._set_status("Detectando anomalías...")
        self._log("🚨 Iniciando detección", "header")
        
        threading.Thread(target=self._detectar_thread, args=(archivo,), daemon=True).start()
    
    def _detectar_thread(self, archivo):
        try:
            # Cargar IPs spoofed
            ips_spoofed = None
            if self.spoofed_var.get() and os.path.exists(self.spoofed_var.get()):
                with open(self.spoofed_var.get(), 'r') as f:
                    ips_spoofed = set(line.strip() for line in f if not line.startswith('#'))
                self._log(f"📋 Cargadas {len(ips_spoofed)} IPs spoofed")
            
            from m3_detector_anomalias import detectar_anomalias_pcap, imprimir_metricas
            
            resultados, self.metricas = detectar_anomalias_pcap(
                archivo,
                etiquetas_spoofed=ips_spoofed,
                verbose=True
            )
            
            self._mostrar_metricas()
            self._log("✅ Detección completada", "success")
            self._set_status(f"Anomalías: {self.metricas.tp} detectadas")
            
        except Exception as e:
            self._log(f"❌ Error: {e}", "error")
            self._set_status("Error en detección")
        finally:
            self.detectando = False
            self.btn_detectar.config(state=tk.NORMAL)
    
    def _mostrar_metricas(self):
        if not self.metricas:
            return
        
        m = self.metricas
        metricas_data = {
            "TPR (Recall)": f"{m.tpr*100:.1f}%",
            "FPR": f"{m.fpr*100:.1f}%",
            "Precisión": f"{m.precision*100:.1f}%",
            "TP": str(m.tp),
            "FP": str(m.fp),
            "FN": str(m.fn),
            "TN": str(m.tn),
            "Latencia": f"{m.latencia_promedio:.2f}ms"
        }
        
        for label, valor in metricas_data.items():
            if label in self.metricas_labels:
                self.metricas_labels[label].config(text=valor)
        
        self._log("=" * 70, "header")
        self._log("📊 MÉTRICAS DE DETECCIÓN", "header")
        self._log("=" * 70, "header")
        self._log(f"  TPR: {m.tpr*100:.1f}%")
        self._log(f"  FPR: {m.fpr*100:.1f}%")
        self._log(f"  Precisión: {m.precision*100:.1f}%")
        self._log(f"  Latencia: {m.latencia_promedio:.3f}ms")
        self._log("=" * 70, "header")
    
    # ── Funciones de herramientas ──
    
    def _generar_spoofing(self):
        dst = simpledialog.askstring("Destino", "IP destino:", initialvalue="192.168.100.20")
        if not dst:
            return
        
        count = simpledialog.askinteger("Cantidad", "Número de paquetes:", initialvalue=50)
        if not count:
            return
        
        self._log(f"🚨 Generando {count} spoofed → {dst}", "header")
        self._set_status("Generando spoofing...")
        
        threading.Thread(target=self._generar_spoofing_thread, args=(dst, count), daemon=True).start()
    
    def _generar_spoofing_thread(self, dst, count):
        try:
            from m3_detector_anomalias import generar_trafico_spoofed
            generar_trafico_spoofed(dst, count, self.iface_var.get())
            self._log(f"✅ {count} paquetes spoofed enviados", "success")
            self._set_status("Spoofing completado")
        except Exception as e:
            self._log(f"❌ Error: {e}", "error")
            self._set_status("Error en spoofing")
    
    def _generar_legitimo(self):
        dst = simpledialog.askstring("Destino", "IP destino:", initialvalue="192.168.100.20")
        if not dst:
            return
        
        count = simpledialog.askinteger("Cantidad", "Número de paquetes:", initialvalue=50)
        if not count:
            return
        
        self._log(f"📡 Generando {count} legítimos → {dst}", "header")
        self._set_status("Generando tráfico legítimo...")
        
        threading.Thread(target=self._generar_legitimo_thread, args=(dst, count), daemon=True).start()
    
    def _generar_legitimo_thread(self, dst, count):
        try:
            from m3_detector_anomalias import generar_trafico_legitimo
            generar_trafico_legitimo(dst, count, self.iface_var.get())
            self._log(f"✅ {count} paquetes legítimos enviados", "success")
            self._set_status("Tráfico legítimo completado")
        except Exception as e:
            self._log(f"❌ Error: {e}", "error")
            self._set_status("Error generando tráfico")
    
    def _validar_tshark(self):
        archivo = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
        if not archivo:
            return
        
        self._log(f"🔍 Validando contra tshark: {os.path.basename(archivo)}", "header")
        self._set_status("Validando con tshark...")
        
        try:
            # Ejecutar tshark
            cmd = ["tshark", "-r", archivo, "-T", "fields", 
                   "-e", "ip.src", "-e", "ip.dst", "-e", "ip.ttl"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                self._log(f"📊 Tshark: {len(lines)} paquetes analizados")
                for line in lines[:10]:
                    self._log(f"  {line}")
                self._log(f"  ... ({len(lines)} total)")
            else:
                self._log("⚠️ No se obtuvieron resultados de tshark")
            
            self._set_status("Validación completada")
            
        except FileNotFoundError:
            self._log("❌ tshark no instalado. Ejecute: sudo apt install tshark", "error")
            self._set_status("tshark no disponible")
        except Exception as e:
            self._log(f"❌ Error: {e}", "error")
            self._set_status("Error en validación")
    
    # ── Funciones de utilidad ──
    
    def _limpiar_consola(self):
        self.consola.delete(1.0, tk.END)
    
    def _capturar_pantalla(self):
        archivo = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")]
        )
        if archivo:
            try:
                import PIL.ImageGrab
                x = self.root.winfo_rootx()
                y = self.root.winfo_rooty()
                w = self.root.winfo_width()
                h = self.root.winfo_height()
                PIL.ImageGrab.grab(bbox=(x, y, x+w, y+h)).save(archivo)
                self._log(f"📸 Captura guardada: {archivo}", "success")
            except:
                self._log("⚠️ PIL no instalado. pip install pillow", "warning")
    
    def _guardar_reporte(self):
        archivo = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("JSON files", "*.json")]
        )
        if not archivo:
            return
        
        reporte = {
            "fecha": datetime.datetime.now().isoformat(),
            "paquetes_capturados": len(self.paquetes_capturados),
            "analizados": len(self.resultados_analisis)
        }
        
        if self.metricas:
            reporte["metricas"] = {
                "tp": self.metricas.tp,
                "fp": self.metricas.fp,
                "fn": self.metricas.fn,
                "tn": self.metricas.tn,
                "tpr": self.metricas.tpr,
                "fpr": self.metricas.fpr,
                "precision": self.metricas.precision,
                "latencia_promedio": self.metricas.latencia_promedio
            }
        
        if archivo.endswith('.html'):
            self._generar_html_reporte(archivo, reporte)
        else:
            with open(archivo, 'w') as f:
                json.dump(reporte, f, indent=2)
        
        self._log(f"📁 Reporte guardado: {archivo}", "success")
    
    def _generar_html_reporte(self, archivo, data):
        html = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Reporte IP Analyzer</title>
        <style>body{{font-family:Arial;padding:20px;}} table{{border-collapse:collapse;}}
        td,th{{border:1px solid #ddd;padding:8px;text-align:left;}}
        th{{background:#4CAF50;color:white;}}</style></head>
        <body>
        <h1>📊 Reporte de Análisis IP</h1>
        <p><b>Fecha:</b> {data['fecha']}</p>
        <p><b>Paquetes capturados:</b> {data['paquetes_capturados']}</p>
        <p><b>Paquetes analizados:</b> {data['analizados']}</p>
        """
        
        if 'metricas' in data:
            html += "<h2>Métricas de Detección</h2><table>"
            for k, v in data['metricas'].items():
                html += f"<tr><td>{k}</td><td>{v}</td></tr>"
            html += "</table>"
        
        html += "</body></html>"
        with open(archivo, 'w') as f:
            f.write(html)
    
    def _abrir_pcap(self):
        archivo = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
        if archivo:
            self.pcap_var.set(archivo)
            self.detect_pcap_var.set(archivo)
            self._log(f"📂 Abierto: {os.path.basename(archivo)}", "info")
    
    def _mostrar_acerca(self):
        messagebox.showinfo(
            "Acerca de",
            "IF5000 — Analizador de Protocolo IP\n"
            "Grupo 3 | Protocolo IP (RFC 791)\n"
            "Redes y Comunicación de Datos\n"
            "Universidad de Costa Rica, Sede del Sur\n"
            "2026"
        )
    
    def _mostrar_rfc(self):
        messagebox.showinfo(
            "RFC 791",
            "El Protocolo de Internet (IP) es definido en la RFC 791.\n"
            "Puede consultar el documento completo en:\n"
            "https://www.rfc-editor.org/rfc/rfc791.txt"
        )