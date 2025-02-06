import sys
import os

# Añadir la carpeta padre (donde está 'package') a sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)  # Subir un nivel desde 'src'
sys.path.insert(0, parent_dir)

import json
import tkinter as tk
from tkinter import messagebox, filedialog
from datetime import datetime
from package.sphincs import Sphincs  # Importar la clase Sphincs

class AutoFirmaApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AutoFirma - Sphincs")
        self.root.geometry("600x400")
        self.root.resizable(False, False)

        # Instancia de Sphincs
        self.sphincs = Sphincs()

        # Título
        self.title_label = tk.Label(
            root, text="AutoFirma con Sphincs", font=("Arial", 16, "bold")
        )
        self.title_label.pack(pady=10)

        # Botón para firmar un mensaje
        self.sign_message_button = tk.Button(
            root,
            text="Firmar Mensaje",
            font=("Arial", 12),
            command=self.sign_message,
            bg="#28A745",
            fg="white",
            width=20,
        )
        self.sign_message_button.pack(pady=10)

        # Botón para verificar la firma
        self.verify_signature_button = tk.Button(
            root,
            text="Verificar Firma",
            font=("Arial", 12),
            command=self.verify_signature,
            bg="#FFC107",
            fg="black",
            width=20,
        )
        self.verify_signature_button.pack(pady=10)

        # Área de texto para logs
        self.log_text = tk.Text(root, width=70, height=15, state=tk.DISABLED)
        self.log_text.pack(pady=10)

    def log_message(self, message):
        """Añade mensajes al área de logs."""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)

    def load_certificate(self):
        """Carga la SK y PK del usuario desde el certificado."""
        try:
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            cert_files = [f for f in os.listdir(desktop_path) if f.startswith("certificado_digital_") and f.endswith(".json")]
            if not cert_files:
                raise FileNotFoundError("No se encontraron certificados en el escritorio.")
            cert_path = os.path.join(desktop_path, filedialog.askopenfilename(title="Seleccionar certificado", initialdir=desktop_path, filetypes=[("Certificados", "certificado_digital_*.json")]))
            if not os.path.exists(cert_path):
                raise FileNotFoundError("No se encontró el certificado en el escritorio.")

            with open(cert_path, "r") as cert_file:
                cert_data = json.load(cert_file)

            user_sk = bytes.fromhex(cert_data["user_secret_key"])
            user_pk = bytes.fromhex(cert_data["user_public_key"])
            exp_date = datetime.fromisoformat(cert_data["fecha_caducidad"])
            issue_date = datetime.fromisoformat(cert_data["fecha_expedicion"])


            self.log_message(f"Clave privada cargada: {user_sk.hex()}")
            self.log_message(f"Clave pública cargada: {user_pk.hex()}")
            
            return user_sk, user_pk, issue_date, exp_date
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar certificado: {e}")
            self.log_message(f"Error al cargar certificado: {e}")
            return None, None, None, None

    def sign_message(self):
        """Firma un mensaje utilizando la clave privada del usuario."""
        try:
            # Cargar claves desde el certificado
            user_sk, _, _, _ = self.load_certificate()
            if not user_sk:
                return

            # Seleccionar mensaje
            message = filedialog.askopenfilename(
                title="Seleccionar archivo para firmar",
                filetypes=(("Archivos pdf", "*.pdf"), ("Todos los archivos", "*.*")),
            )
            if not message:
                return

            with open(message, "rb") as f:
                data = f.read()

            # Generar firma
            signature = self.sphincs.sign(data, user_sk)

            # Guardar firma en el escritorio
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            signature_path = os.path.join(desktop_path, "firma.sig")
            with open(signature_path, "wb") as sig_file:
                sig_file.write(signature)

            self.log_message(f"Mensaje firmado con éxito.\nFirma guardada en: {signature_path}")
            messagebox.showinfo("Éxito", f"Firma generada y guardada en {signature_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al firmar mensaje: {e}")
            self.log_message(f"Error al firmar mensaje: {e}")

    def verify_signature(self):
        """Verifica una firma utilizando la clave pública del usuario."""
        try:
            # Cargar claves desde el certificado
            _, user_pk, issue_date, exp_date = self.load_certificate()
            if not user_pk:
                return

            current_date = datetime.now()
            if current_date < issue_date or current_date > exp_date:
                messagebox.showwarning("Verificación", "El certificado ha expirado o aún no es válido.")
                self.log_message("La firma no es válida debido a la fecha de expiración o emisión.")
                return

            # Leer firma
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            signature_path = os.path.join(desktop_path, "firma.sig")

            if not os.path.exists(signature_path):
                raise FileNotFoundError("No se encontró la firma en el escritorio.")

            with open(signature_path, "rb") as sig_file:
                signature = sig_file.read()

            # Seleccionar mensaje
            message = filedialog.askopenfilename(
                title="Seleccionar archivo para verificar",
                filetypes=(("Archivos pdf", "*.pdf"), ("Todos los archivos", "*.*")),
            )
            if not message:
                return

            with open(message, "rb") as f:
                data = f.read()

            # Verificar firma
            is_valid = self.sphincs.verify(data, signature, user_pk)
            if is_valid:
                messagebox.showinfo("Verificación", "La firma es válida.")
                self.log_message("Verificación exitosa: La firma es válida.")
            else:
                messagebox.showwarning("Verificación", "La firma no es válida.")
                self.log_message("La firma no es válida.")
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar firma: {e}")
            self.log_message(f"Error al verificar firma: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AutoFirmaApp(root)
    root.mainloop()
