import sys
import os

# Añadir la carpeta padre (donde está 'package') a sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)  # Subir un nivel desde 'src'
sys.path.insert(0, parent_dir)

import json
import datetime
import hashlib
import tkinter as tk
from Crypto.Cipher import AES
import base64
import secrets
from tkinter import simpledialog
from tkinter import messagebox
from package.sphincs import Sphincs  # Importar la clase Sphincs

# Rutas de los archivos donde guardaremos las claves de la entidad
SK_ENTIDAD_PATH = "sk_entidad.json"
PK_ENTIDAD_PATH = "pk_entidad.json"

sphincs_instancia = Sphincs()

def generar_claves_entidad():
    """Genera nuevas claves de la entidad y las guarda en archivos separados."""
    sk, pk = sphincs_instancia.generate_key_pair()

    with open(SK_ENTIDAD_PATH, "w") as sk_file:
        json.dump({"sk": sk.hex()}, sk_file)

    with open(PK_ENTIDAD_PATH, "w") as pk_file:
        json.dump({"pk": pk.hex()}, pk_file)

    global ENTIDAD_SK, ENTIDAD_PK
    ENTIDAD_SK, ENTIDAD_PK = sk, pk

    messagebox.showinfo("Éxito", "Nuevas claves de entidad generadas correctamente.")

def leer_claves_entidad():
    """Lee las claves de la entidad generadora si existen. Retorna (sk, pk) o None si alguna falta."""
    if not os.path.exists(SK_ENTIDAD_PATH) or not os.path.exists(PK_ENTIDAD_PATH):
        return None, None  # Indica que falta una clave y hay que generarla

    with open(SK_ENTIDAD_PATH, "r") as sk_file, open(PK_ENTIDAD_PATH, "r") as pk_file:
        sk = bytes.fromhex(json.load(sk_file)["sk"])
        pk = bytes.fromhex(json.load(pk_file)["pk"])
        return sk, pk

# Intentar leer claves existentes
ENTIDAD_SK, ENTIDAD_PK = leer_claves_entidad()

class CertificadoDigitalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Generador de Certificados Digitales - Sphincs")
        self.root.geometry("600x500")
        self.root.resizable(False, False)

        # Instancia de Sphincs
        self.sphincs = sphincs_instancia

        # Título
        self.title_label = tk.Label(
            root, text="Generador de Certificados Digitales", font=("Arial", 16, "bold")
        )
        self.title_label.pack(pady=10)

        # Botón para generar claves de la entidad (ahora está arriba)
        self.generate_keys_button = tk.Button(
            root,
            text="Generar Claves de Entidad",
            font=("Arial", 12),
            command=generar_claves_entidad,  # Llama directamente al único método
            bg="#D9534F",
            fg="white",
            width=25,
        )
        self.generate_keys_button.pack(pady=10)

        # Verificar si existen las claves, si no, mostrar advertencia
        global ENTIDAD_SK, ENTIDAD_PK
        if ENTIDAD_SK is None or ENTIDAD_PK is None:
            messagebox.showwarning(
                "Faltan claves", "No se encontraron claves de la entidad. Debes generarlas."
            )

        # Campos para nombre y DNI (ahora están debajo del botón)
        self.name_label = tk.Label(root, text="Nombre:", font=("Arial", 12))
        self.name_label.pack()
        self.name_entry = tk.Entry(root, font=("Arial", 12))
        self.name_entry.pack(pady=5)

        self.dni_label = tk.Label(root, text="DNI:", font=("Arial", 12))
        self.dni_label.pack()
        self.dni_entry = tk.Entry(root, font=("Arial", 12))
        self.dni_entry.pack(pady=5)

        # Botón para generar certificado
        self.generate_cert_button = tk.Button(
            root,
            text="Generar Certificado",
            font=("Arial", 12),
            command=self.generate_certificate,
            bg="#0078D4",
            fg="white",
            width=20,
        )
        self.generate_cert_button.pack(pady=10)

        # Área de texto para logs
        self.log_text = tk.Text(root, width=70, height=15, state=tk.DISABLED)
        self.log_text.pack(pady=10)

    def log_message(self, message):
        """Añade mensajes al área de logs."""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)

    def calcular_hash(self, data):
        """Calcula el hash SHA-256 de los datos serializados asegurando el mismo orden."""
        ordered_keys = [
            "nombre",
            "fecha_expedicion",
            "fecha_caducidad",
            "user_public_key",
            "entity_public_key",
            "firma",
            "user_secret_key"
        ]
        ordered_data = {key: data[key] for key in ordered_keys if key in data}
        serialized_data = json.dumps(ordered_data, separators=(",", ":"), ensure_ascii=False)

        # Guardar en un archivo para comparar con la verificación
        #with open(f"serializado_generacion_huella.json", "w", encoding="utf-8") as f:
        #    f.write(serialized_data)

        return hashlib.sha256(serialized_data.encode()).hexdigest()

    def encrypt_private_key(self, secret_key, password):
        """Cifra la clave privada con AES-256 en modo CBC usando una contraseña."""
        try:
            # Generar un salt aleatorio de 16 bytes
            salt = secrets.token_bytes(16)

            # Generar un hash de la contraseña con el salt para usarlo como clave AES (256 bits)
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

            # Añadir padding con los últimos 50 bits duplicados
            padding = secret_key[-7:]  # 50 bits (aprox. 7 bytes)
            secret_key_padded = secret_key + padding

            # Generar un IV aleatorio de 16 bytes
            iv = secrets.token_bytes(16)

            # Crear el cifrador AES en modo CBC
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # Asegurar que el texto a cifrar es múltiplo de 16 bytes (padding PKCS7)
            pad_length = 16 - (len(secret_key_padded) % 16)
            secret_key_padded += bytes([pad_length] * pad_length)

            # Cifrar la clave privada
            encrypted_data = cipher.encrypt(secret_key_padded)

            # Guardar SALT + IV + datos cifrados en Base64 para facilitar almacenamiento
            return base64.b64encode(salt + iv + encrypted_data).decode()

        except Exception as e:
            raise ValueError(f"Error al cifrar clave privada: {e}")

    def validate_password(self, password):
        """Valida que la contraseña cumpla con los requisitos mínimos de seguridad."""
        if len(password) < 8:
            return False, "La contraseña debe tener al menos 8 caracteres."
        
        if not any(c.isupper() for c in password):
            return False, "La contraseña debe contener al menos una letra mayúscula."
        
        if not any(c.isdigit() for c in password):
            return False, "La contraseña debe contener al menos un número."
        
        if not any(c in '!@#$%^&*()_-+=[]{}|:;<>,.?/~`' for c in password):
            return False, "La contraseña debe contener al menos un carácter especial."
        
        return True, "Contraseña válida"

    def generate_certificate(self):
        """Genera dos certificados digitales: uno para firma y otro para autenticación."""
        try:
            # Obtener datos del usuario
            nombre = self.name_entry.get().strip()
            dni = self.dni_entry.get().strip()
            if not nombre or not dni:
                raise ValueError("El nombre y el DNI son obligatorios.")
            
            # Solicitar contraseña de cifrado al usuario con validación
            password = None
            while password is None:
                password = simpledialog.askstring("Contraseña", 
                                                "Introduce una contraseña para cifrar la clave privada:\n\n"
                                                "La contraseña debe tener:\n"
                                                "- Al menos 8 caracteres\n"
                                                "- Al menos una letra mayúscula\n"
                                                "- Al menos un número\n"
                                                "- Al menos un carácter especial (ej: !@#$%^&*)", 
                                                show="*")
                
                if password is None:  # Usuario canceló el diálogo
                    return
                
                valid, message = self.validate_password(password)
                if not valid:
                    messagebox.showerror("Contraseña insegura", message)
                    password = None

            # Generar clave privada y pública del usuario
            user_sk, user_pk = self.sphincs.generate_key_pair()

            # Fechas de expedición y caducidad
            fecha_expedicion = datetime.date.today().isoformat()
            fecha_caducidad = (datetime.date.today() + datetime.timedelta(days=2*365)).isoformat()

            # Crear estructura del certificado SIN la clave privada (para autenticación)
            certificado_autenticacion = {
                "nombre": nombre,
                "fecha_expedicion": fecha_expedicion,
                "fecha_caducidad": fecha_caducidad,
                "user_public_key": user_pk.hex(),
                "entity_public_key": ENTIDAD_PK.hex()
            }

            # --------- Generar HASH PARA FIRMA (EXCLUYENDO firma y huella) ---------
            ordered_keys_firma = ["nombre", "fecha_expedicion", "fecha_caducidad", "user_public_key", "entity_public_key"]
            ordered_data_firma = {key: certificado_autenticacion[key] for key in ordered_keys_firma}

            serialized_data_firma = json.dumps(ordered_data_firma, separators=(",", ":"), ensure_ascii=False)
            hash_certificado = hashlib.sha256(serialized_data_firma.encode()).digest()

            # Guardar en archivo para depuración
            # with open("serializado_generacion_firma.json", "w", encoding="utf-8") as f:
            #    f.write(serialized_data_firma)

            firma = self.sphincs.sign(hash_certificado, ENTIDAD_SK)

            # Agregar firma al certificado de autenticación
            certificado_autenticacion["firma"] = firma.hex()

            # Calcular huella digital (hash de todo el certificado de autenticación)
            certificado_autenticacion["huella_digital"] = self.calcular_hash(certificado_autenticacion)

            user_sk_encrypted = self.encrypt_private_key(user_sk, password)

            # Crear certificado de firma (incluye la clave privada del usuario)
            certificado_firma = certificado_autenticacion.copy()
            certificado_firma["user_secret_key"] = user_sk_encrypted  # Solo en el certificado de firma

            # Calcular huella digital (hash de todo el certificado de firma)
            certificado_firma["huella_digital"] = self.calcular_hash(certificado_firma)

            # Guardar certificados en el escritorio
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            cert_auth_path = os.path.join(desktop_path, f"certificado_digital_autenticacion_{dni}.json")
            cert_sign_path = os.path.join(desktop_path, f"certificado_digital_firmar_{dni}.json")

            with open(cert_auth_path, "w") as cert_auth_file:
                json.dump(certificado_autenticacion, cert_auth_file, indent=4)

            with open(cert_sign_path, "w") as cert_sign_file:
                json.dump(certificado_firma, cert_sign_file, indent=4)

            self.log_message(f"Certificados generados y guardados en:\n- {cert_auth_path}\n- {cert_sign_path}")
            messagebox.showinfo("Éxito", f"Certificados generados con éxito:\n{cert_auth_path}\n{cert_sign_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar certificados: {e}")
            self.log_message(f"Error al generar certificados: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CertificadoDigitalApp(root)
    root.mainloop()
