#!/usr/bin/env python3
"""
=============================================================================
Lanzador del Analizador IP — IF5000 Grupo 3
=============================================================================
Ejecutar: python3 run.py
"""

import sys
import os

# Agregar módulos al path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'módulos'))

print(f"📁 Directorio actual: {os.getcwd()}")
print(f"📁 Archivos en módulos/: {os.listdir('módulos') if os.path.exists('módulos') else 'No existe'}")

try:
    # CAMBIADO: GUI en lugar de gui_ip_analyzer
    from GUI import IPAnalyzerGUI
    print("✅ GUI importada correctamente")
except ImportError as e:
    print(f"❌ Error importando GUI: {e}")
    print("\nPosibles soluciones:")
    print("1. Verifique que el archivo existe: módulos/GUI.py")
    print("2. Revise que la clase se llame 'IPAnalyzerGUI'")
    print("3. Revise que no haya errores de sintaxis en el archivo")
    sys.exit(1)

if __name__ == "__main__":
    import tkinter as tk
    root = tk.Tk()
    app = IPAnalyzerGUI(root)
    root.mainloop()