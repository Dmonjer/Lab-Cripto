import sys

def cifrar_cesar(texto, desplazamiento):
    resultado = ""
    for caracter in texto:
        # Verificamos si es una letra para no alterar los espacios
        if caracter.isalpha():
            ascii_base = ord('a') if caracter.islower() else ord('A')
            # Aplicamos la fórmula del cifrado César (módulo 26 para el abecedario inglés)
            nuevo_caracter = chr((ord(caracter) - ascii_base + desplazamiento) % 26 + ascii_base)
            resultado += nuevo_caracter
        else:
            # Si es un espacio o símbolo, lo dejamos igual
            resultado += caracter
    return resultado

# Verificamos que se entreguen los parámetros correctos
if len(sys.argv) != 3:
    print("Uso: python3 cesar.py <texto> <desplazamiento>")
    sys.exit(1)

# Asignamos los parámetros ingresados en la terminal
texto_original = sys.argv[1]
desplazamiento = int(sys.argv[2])

# Imprimimos el resultado
texto_cifrado = cifrar_cesar(texto_original, desplazamiento)
print(texto_cifrado)