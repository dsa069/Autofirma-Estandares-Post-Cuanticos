import sys
import os

# Añadir la carpeta padre (donde está 'package') a sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)  # Subir un nivel desde 'src'
sys.path.insert(0, parent_dir)

import json
import datetime
import tkinter as tk
from tkinter import messagebox, filedialog
from package.sphincs import Sphincs  # Importar la clase Sphincs

class CertificadoDigitalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Generador de Certificados Digitales - Sphincs")
        self.root.geometry("600x500")
        self.root.resizable(False, False)

        # Instancia de Sphincs
        self.sphincs = Sphincs()

        # Título
        self.title_label = tk.Label(
            root, text="Generador de Certificados Digitales", font=("Arial", 16, "bold")
        )
        self.title_label.pack(pady=10)

        # Campos para nombre y DNI
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

    def generate_certificate(self):
        """Genera un certificado digital firmado por la entidad certificadora."""
        try:
            # Obtener datos del usuario
            nombre = self.name_entry.get().strip()
            dni = self.dni_entry.get().strip()
            if not nombre or not dni:
                raise ValueError("El nombre y el DNI son obligatorios.")

            # Generar clave privada y pública del usuario
            user_sk, user_pk = self.sphincs.generate_key_pair()

            # Fechas de expedición y caducidad
            fecha_expedicion = datetime.date.today().isoformat()
            fecha_caducidad = (datetime.date.today() + datetime.timedelta(days=2*365)).isoformat()

            # Crear estructura del certificado
            certificado = {
                "nombre": nombre,
                "dni": dni,
                "fecha_expedicion": fecha_expedicion,
                "fecha_caducidad": fecha_caducidad,
                "user_public_key": user_pk.hex(),
                "user_secret_key": user_sk.hex(),
            }

            # Convertir a JSON
            certificado_json = json.dumps(certificado, indent=4)

            # Firmar el certificado con la clave privada de la entidad
            firma = self.sphincs.sign(certificado_json.encode(), user_sk)
            certificado["firma"] = firma.hex()

            # Guardar certificado en el escritorio
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            cert_path = os.path.join(desktop_path, "certificado_digital_"+ dni +".json")
            with open(cert_path, "w") as cert_file:
                json.dump(certificado, cert_file, indent=4)

            self.log_message(f"Certificado generado y guardado en: {cert_path}")
            messagebox.showinfo("Éxito", f"Certificado generado con éxito en: {cert_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar certificado: {e}")
            self.log_message(f"Error al generar certificado: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CertificadoDigitalApp(root)
    root.mainloop()
