# test_captura.py - Script para encontrar la interfaz que funciona en Windows
from scapy.all import get_if_list, sniff, IP

print("=" * 60)
print("🔍 PROBANDO INTERFACES DE RED EN WINDOWS")
print("=" * 60)

# Mostrar todas las interfaces disponibles
print("\n📡 Interfaces disponibles:")
for i, iface in enumerate(get_if_list()):
    print(f"  {i}: {iface}")

print("\n" + "=" * 60)
print("🔍 Probando cada interfaz (excepto loopback)...")
print("=" * 60)

interfaz_funcional = None

for iface in get_if_list():
    # Saltar loopback
    if 'Loopback' in iface:
        print(f"\n⏭️ Saltando loopback: {iface}")
        continue
    
    print(f"\n📡 Probando: {iface}")
    print(f"   (Capturando por 3 segundos...)")
    
    try:
        paquetes = []
        
        def callback(pkt):
            if IP in pkt:
                paquetes.append(pkt)
                print(f"   📦 {pkt[IP].src} → {pkt[IP].dst}")
        
        # Intentar capturar por 3 segundos
        sniff(iface=iface, count=5, timeout=3, prn=callback)
        
        if paquetes:
            print(f"\n✅ ¡ESTA INTERFAZ FUNCIONA!")
            print(f"   Interfaz: {iface}")
            print(f"   Paquetes capturados: {len(paquetes)}")
            interfaz_funcional = iface
            break
        else:
            print(f"   ⚠️ No se capturaron paquetes (puede no haber tráfico)")
            
    except Exception as e:
        print(f"   ❌ Error: {e}")

# Resultado final
print("\n" + "=" * 60)
if interfaz_funcional:
    print(f"✅ INTERFAZ ENCONTRADA: {interfaz_funcional}")
    print("\n📌 COPIA ESTE UUID y pégalo en la GUI en el campo 'Interfaz'")
else:
    print("❌ No se encontró ninguna interfaz funcional")
    print("\n📌 Posibles soluciones:")
    print("   1. Ejecuta el script como Administrador")
    print("   2. Verifica que Npcap esté instalado")
    print("   3. Usa el MODO SIMULACIÓN en la GUI")
print("=" * 60)