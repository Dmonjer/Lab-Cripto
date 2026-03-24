import sys
from scapy.all import rdpcap, ICMP, Raw

def descifrar_cesar(texto, desplazamiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            ascii_base = ord('a') if caracter.islower() else ord('A')
            # Restamos el desplazamiento para descifrar
            nuevo_caracter = chr((ord(caracter) - ascii_base - desplazamiento) % 26 + ascii_base)
            resultado += nuevo_caracter
        else:
            resultado += caracter
    return resultado

archivo_pcap = "cesar.pcapng"

try:
    # Leemos la captura de red
    paquetes = rdpcap(archivo_pcap)
except FileNotFoundError:
    print(f"Error: No se encontró el archivo {archivo_pcap}. Asegúrate de haberlo guardado.")
    sys.exit(1)

mensaje_interceptado = ""

# Extraemos el mensaje paquete por paquete
for pkt in paquetes:
    # Filtramos: Solo ICMP tipo 8 (Echo Request) que contengan datos (Raw)
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and pkt.haslayer(Raw):
        payload = pkt[Raw].load
        # Asumiendo que extraemos el primer byte de cada paquete modificado
        # Filtramos para asegurarnos de que sea un caracter ascii válido
        if len(payload) > 0:
            char_ascii = payload[0]
            if 32 <= char_ascii <= 126: # Rango de caracteres imprimibles
                mensaje_interceptado += chr(char_ascii)

# Limpiamos posibles caracteres basura de pings reales que se hayan colado al final o principio
# Sabiendo que el mensaje de prueba termina en 'b', tomamos el texto hasta la primera 'b'
if 'b' in mensaje_interceptado:
    indice_fin = mensaje_interceptado.rfind('b') + 1
    mensaje_interceptado = mensaje_interceptado[:indice_fin]
else:
    # Si por alguna razón no detecta el fin, nos quedamos con los primeros 33 caracteres (largo del texto)
    mensaje_interceptado = mensaje_interceptado[:33]

print(f"{mensaje_interceptado}")

# Códigos ANSI para colores en la terminal
COLOR_VERDE = '\033[92m'
COLOR_RESET = '\033[0m'

# Fuerza bruta (25 combinaciones posibles)
for i in range(1, 26):
    intento = descifrar_cesar(mensaje_interceptado, i)
    
    # Lógica para detectar el mensaje más probable (buscamos palabras clave)
    if "seguridad" in intento or "criptografia" in intento or "redes" in intento:
        # Imprimimos en verde la opción correcta
        print(f"{i:02d} {COLOR_VERDE}{intento}{COLOR_RESET}")
    else:
        # Imprimimos normal
        print(f"{i:02d} {intento}")