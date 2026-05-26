from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import sys

# --- Constantes ---
AES_KEY_SIZE = 32  # AES-256
DES_KEY_SIZE = 8   # DES
TDES_KEY_SIZE = 24 # 3DES (Opción de 3 claves)

# Tamaños de bloque (IV) en bytes
AES_BLOCK_SIZE = 16 # AES usa bloques de 128 bits
DES_BLOCK_SIZE = 8  # DES y 3DES usan bloques de 64 bits


def adjust_bytes(data: bytes, required_size: int, data_name: str = "Data") -> bytes:

    data_len = len(data)
    
    if data_len < required_size:
        padding_size = required_size - data_len
        random_padding = get_random_bytes(padding_size)
        adjusted_data = data + random_padding
        print(f"'{data_name}' ({data_len}B) es corta. Rellenando con {padding_size} bytes aleatorios.")
    
    elif data_len > required_size:
        adjusted_data = data[:required_size]
        print(f"'{data_name}' ({data_len}B) es larga. Truncando a {required_size} bytes.")
    
    else:
        adjusted_data = data
        print(f"'{data_name}' ({data_len}B) tiene el tamaño correcto.")
        
    return adjusted_data

# --- Funciones de Cifrado y Descifrado ---

def encrypt_decrypt_aes(key: bytes, iv: bytes, plaintext: bytes):
    """Implementa cifrado/descifrado AES-256 CBC"""
    print("\n--- Ejecutando AES-256 ---")
    try:
        # Cifrado
        cipher_encrypt = AES.new(key, AES.MODE_CBC, iv)
        padded_text = pad(plaintext, AES_BLOCK_SIZE)
        ciphertext = cipher_encrypt.encrypt(padded_text)
        print(f"Texto Cifrado (hex): {ciphertext.hex()}")

        # Descifrado
        cipher_decrypt = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded_text = cipher_decrypt.decrypt(ciphertext)
        decrypted_text = unpad(decrypted_padded_text, AES_BLOCK_SIZE)
        print(f"Texto Descifrado: {decrypted_text.decode('utf-8')}")

    except ValueError as e:
        print(f"Error en AES: {e}. (Verifique el tamaño de la clave/IV)")

def encrypt_decrypt_3des(key: bytes, iv: bytes, plaintext: bytes):
    """Implementa cifrado/descifrado 3DES CBC"""
    print("\n--- Ejecutando 3DES ---")
    try:
        # Cifrado
        cipher_encrypt = DES3.new(key, DES3.MODE_CBC, iv)
        padded_text = pad(plaintext, DES_BLOCK_SIZE)
        ciphertext = cipher_encrypt.encrypt(padded_text)
        print(f"Texto Cifrado (hex): {ciphertext.hex()}")

        # Descifrado
        cipher_decrypt = DES3.new(key, DES3.MODE_CBC, iv)
        decrypted_padded_text = cipher_decrypt.decrypt(ciphertext)
        decrypted_text = unpad(decrypted_padded_text, DES_BLOCK_SIZE)
        print(f"Texto Descifrado: {decrypted_text.decode('utf-8')}")

    except ValueError as e:
        print(f"Error en 3DES: {e}. (Verifique el tamaño de la clave/IV)")

def encrypt_decrypt_des(key: bytes, iv: bytes, plaintext: bytes):
    """Implementa cifrado/descifrado DES CBC"""
    print("\n--- Ejecutando DES ---")
    try:
        # Cifrado
        cipher_encrypt = DES.new(key, DES.MODE_CBC, iv)
        padded_text = pad(plaintext, DES_BLOCK_SIZE)
        ciphertext = cipher_encrypt.encrypt(padded_text)
        print(f"Texto Cifrado (hex): {ciphertext.hex()}")

        # Descifrado
        cipher_decrypt = DES.new(key, DES.MODE_CBC, iv)
        decrypted_padded_text = cipher_decrypt.decrypt(ciphertext)
        decrypted_text = unpad(decrypted_padded_text, DES_BLOCK_SIZE)
        print(f"Texto Descifrado: {decrypted_text.decode('utf-8')}")

    except ValueError as e:
        print(f"Error en DES: {e}. (Verifique el tamaño de la clave/IV)")


def main():
    
    print("--- 2.2. Ingreso de Datos del Usuario ---")
    key_str = input("Ingrese la Key (clave): ")
    iv_str = input("Ingrese el IV (Vector de Inicialización): ")
    text_str = input("Ingrese el Texto a cifrar: ")

    # Convertir inputs a bytes
    key_bytes = key_str.encode('utf-8')
    iv_bytes = iv_str.encode('utf-8')
    text_bytes = text_str.encode('utf-8')

    print("\n-------------------------------------------")

    print("--- 2.3. Validación y Ajuste de Claves ---")
    
    # Ajustar para AES-256
    final_aes_key = adjust_bytes(key_bytes, AES_KEY_SIZE, "Clave AES-256")
    
    # Ajustar para 3DES
    final_3des_key = adjust_bytes(key_bytes, TDES_KEY_SIZE, "Clave 3DES")
    
    # Ajustar para DES
    final_des_key = adjust_bytes(key_bytes, DES_KEY_SIZE, "Clave DES")
    
    print("\n--- Claves Finales Utilizadas (en hex) ---")
    print(f"Clave AES-256: {final_aes_key.hex()}")
    print(f"Clave 3DES:    {final_3des_key.hex()}")
    print(f"Clave DES:     {final_des_key.hex()}")

    print("\n--- Ajustando IVs (necesario para modo CBC) ---")
    final_aes_iv = adjust_bytes(iv_bytes, AES_BLOCK_SIZE, "IV AES")
    final_des_iv = adjust_bytes(iv_bytes, DES_BLOCK_SIZE, "IV DES/3DES")

    print("\n-------------------------------------------")

    print("--- 2.4. Implementación Cifrado/Descifrado ---")
    
    encrypt_decrypt_aes(final_aes_key, final_aes_iv, text_bytes)
    encrypt_decrypt_3des(final_3des_key, final_des_iv, text_bytes)
    encrypt_decrypt_des(final_des_key, final_des_iv, text_bytes)
    

if __name__ == "__main__":
    main()
