import sys
import os

# Añadir la carpeta padre (donde está 'package') a sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)  # Subir un nivel desde 'src'
sys.path.insert(0, parent_dir)

import tkinter as tk
from tkinter import messagebox, filedialog
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

        # Botón para generar claves
        self.generate_keys_button = tk.Button(
            root,
            text="Generar Claves",
            font=("Arial", 12),
            command=self.generate_keys,
            bg="#0078D4",
            fg="white",
            width=20,
        )
        self.generate_keys_button.pack(pady=10)

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
            text="Verificar Documento Firmado",
            font=("Arial", 12),
            command=self.verify_signed_document,
            bg="#FFC107",
            fg="black",
            width=25,
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

    def generate_keys(self):
        """Genera un par de claves y las guarda en el escritorio."""
        try:
            self.sphincs.set_w(4)  # Configuración del parámetro 'w'
            sk, pk = self.sphincs.generate_key_pair()

            # Ruta del escritorio
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")

            # Guardar claves en archivos
            private_key_path = os.path.join(desktop_path, "clave_privada.key")
            public_key_path = os.path.join(desktop_path, "clave_publica.key")

            with open(private_key_path, "wb") as sk_file:
                sk_file.write(sk)

            with open(public_key_path, "wb") as pk_file:
                pk_file.write(pk)

            self.log_message(f"Claves generadas y guardadas en el escritorio:\n"
                             f"- Clave privada: {private_key_path}\n"
                             f"- Clave pública: {public_key_path}")
            messagebox.showinfo(
                "Éxito",
                f"Claves generadas con éxito.\n"
                f"Se han guardado en el escritorio:\n{private_key_path}\n{public_key_path}",
            )
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar claves: {e}")
            self.log_message(f"Error al generar claves: {e}")

    def sign_message(self):
        """Firma un mensaje y genera un archivo firmado con la PK y la firma."""
        try:
            # Leer clave privada
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            private_key_path = os.path.join(desktop_path, "clave_privada.key")
            public_key_path = os.path.join(desktop_path, "clave_publica.key")

            if not os.path.exists(private_key_path):
                raise FileNotFoundError("No se encontró la clave privada en el escritorio.")
            if not os.path.exists(public_key_path):
                raise FileNotFoundError("No se encontró la clave pública en el escritorio.")

            with open(private_key_path, "rb") as sk_file:
                sk = sk_file.read()
            with open(public_key_path, "rb") as pk_file:
                pk = pk_file.read()

            # Seleccionar mensaje
            message = filedialog.askopenfilename(
                title="Seleccionar archivo para firmar",
                filetypes=(("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")),
            )
            if not message:
                return

            with open(message, "rb") as f:
                data = f.read()

            # Generar firma
            signature = self.sphincs.sign(data, sk)

            # Crear documento firmado
            signed_content = (
                f"=== Contenido Original ===\n{data.decode('utf-8')}\n\n"
                f"=== Firma Digital (Hex) ===\n{signature.hex()}\n\n"
                f"=== Clave Pública (Hex) ===\n{pk.hex()}\n"
            )
            signed_file_path = os.path.join(desktop_path, "documento_firmado.txt")
            with open(signed_file_path, "w") as signed_file:
                signed_file.write(signed_content)

            self.log_message(f"Documento firmado con éxito.\nGuardado en: {signed_file_path}")
            messagebox.showinfo("Éxito", f"Documento firmado guardado en: {signed_file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al firmar mensaje: {e}")
            self.log_message(f"Error al firmar mensaje: {e}")

    def verify_signed_document(self):
        """Verifica un archivo firmado directamente desde un archivo de texto."""
        try:
            # Seleccionar archivo firmado
            signed_file_path = filedialog.askopenfilename(
                title="Seleccionar documento firmado",
                filetypes=(("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")),
            )
            if not signed_file_path:
                return

            with open(signed_file_path, "r") as f:
                lines = f.readlines()

            # Extraer las partes clave
            if len(lines) < 3:
                raise ValueError("El archivo no contiene suficiente información para verificar.")

            content = lines[0].strip().encode("utf-8")  # Contenido original en la primera línea
            signature = bytes.fromhex(lines[1].strip())  # Firma en la segunda línea (hexadecimal)
            pk = bytes.fromhex(lines[2].strip())  # Clave pública en la tercera línea (hexadecimal)

            # Verificar firma
            is_valid = self.sphincs.verify(content, signature, pk)
            if is_valid:
                messagebox.showinfo("Verificación", "La firma del documento es válida.")
                self.log_message("Verificación exitosa: La firma es válida.")
            else:
                messagebox.showwarning("Verificación", "La firma del documento no es válida.")
                self.log_message("La firma del documento no es válida.")
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar documento firmado: {e}")
            self.log_message(f"Error al verificar documento firmado: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = AutoFirmaApp(root)
    root.mainloop()