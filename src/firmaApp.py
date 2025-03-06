import sys
import os

# Añadir la carpeta padre (donde está 'package') a sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)  # Subir un nivel desde 'src'
sys.path.insert(0, parent_dir)

import json
import hashlib
import tkinter as tk
from tkinter import messagebox, filedialog
from datetime import datetime
import fitz  # PyMuPDF para manejar metadatos en PDFs
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

    def calcular_hash_firma(self, cert_copy):
        cert_copy.pop("firma", None)
        cert_copy.pop("user_secret_key", None)  # No debe estar en la firma

        ordered_keys_firma = ["nombre", "fecha_expedicion", "fecha_caducidad", "user_public_key", "entity_public_key"]
        ordered_data_firma = {key: cert_copy[key] for key in ordered_keys_firma}

        serialized_data_firma = json.dumps(ordered_data_firma, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(serialized_data_firma.encode()).digest()
    
    def verificar_certificado(self, cert_data):
        """Verifica la validez de un certificado."""
        try:
            expected_hash = cert_data.get("huella_digital")
            firma = cert_data.get("firma")
            ent_pk = bytes.fromhex(cert_data["entity_public_key"])

            # -------------------- VALIDACIÓN HUELLA DIGITAL --------------------
            cert_copy = cert_data.copy()
            cert_copy.pop("huella_digital", None)

            # QUE PASA CON LA SECRET KEY EN EL CASO DE LA VERIFICACION EN EL CERTIFICADO DE AUTENTICACION???????????????
            ordered_keys_huella = ["nombre", "fecha_expedicion", "fecha_caducidad", "user_public_key", "entity_public_key", "firma", "user_secret_key"]
            ordered_data_huella = {key: cert_copy[key] for key in ordered_keys_huella if key in cert_copy}

            serialized_data_huella = json.dumps(ordered_data_huella, separators=(",", ":"), ensure_ascii=False)
            recalculated_hash = hashlib.sha256(serialized_data_huella.encode()).hexdigest()

            #self.log_message(f"Hash recalculado: {recalculated_hash}")

            if recalculated_hash != expected_hash:
                raise ValueError("La huella digital del certificado no es válida.")

            # Guardar en archivo para depuración
            #with open("serializado_huella.json", "w", encoding="utf-8") as f:
            #    f.write(serialized_data_huella)

            # -------------------- VERIFICACIÓN DE FECHAS --------------------
            fecha_expedicion = datetime.fromisoformat(cert_data["fecha_expedicion"])
            fecha_caducidad = datetime.fromisoformat(cert_data["fecha_caducidad"])
            current_date = datetime.now()
            
            if current_date < fecha_expedicion:
                raise ValueError("El certificado aún no es válido (fecha de emisión futura).")

            if current_date > fecha_caducidad:
                raise ValueError("El certificado ha expirado.")
            
            # -------------------- VERIFICACIÓN PK ENTIDAD --------------------
            ent_pk_cert = bytes.fromhex(cert_data["entity_public_key"])  # Clave pública dentro del certificado
            pk_entidad_path = "pk_entidad.json"
            
            if not os.path.exists(pk_entidad_path):
                raise ValueError("No se encontró la clave pública de la entidad.")

            with open(pk_entidad_path, "r") as pk_file:
                ent_pk_real = bytes.fromhex(json.load(pk_file)["pk"])  # Clave pública real de la entidad

            if ent_pk_cert != ent_pk_real:
                raise ValueError("La clave pública de la entidad en el certificado no coincide con la clave pública oficial.")

            # -------------------- VALIDACIÓN FIRMA --------------------
            # -VALIDACION HASH DATOS FIRMA (ESTA BIEN) 
            recalculated_hash_firma = self.calcular_hash_firma(cert_copy)

            #self.log_message(f"Hash recalculado para firma: {recalculated_hash_firma}")

            # Guardar en archivo para depuración
            #with open("serializado_verificacion_firma.json", "w", encoding="utf-8") as f:
            #   f.write(serialized_data_firma)
   
            # Verificar firma usando el hash correcto y la clave pública de la entidad
            firma_bytes = bytes.fromhex(firma)
            firma_valida = self.sphincs.verify(recalculated_hash_firma, firma_bytes, ent_pk)

            if not firma_valida:
                raise ValueError("La firma del certificado no es válida.")

            return True
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar certificado: {e}")
            self.log_message(f"Error al verificar certificado: {e}")
            return False
             
    def load_certificate(self, tipo):
        """Carga el certificado del usuario según el tipo ('firmar' o 'autenticacion')."""
        try:
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            cert_path = filedialog.askopenfilename(
                title="Seleccionar certificado",
                initialdir=desktop_path,
                filetypes=[("Certificados", f"certificado_digital_{tipo}_*.json")]
            )
            if not cert_path:
                return None, None, None, None, None, None

            with open(cert_path, "r") as cert_file:
                cert_data = json.load(cert_file)

            if not self.verificar_certificado(cert_data):
                return None, None, None, None, None, None

            user_sk = bytes.fromhex(cert_data["user_secret_key"]) if tipo == "firmar" else None
            user_pk = bytes.fromhex(cert_data["user_public_key"])
            ent_pk = bytes.fromhex(cert_data["entity_public_key"])
            exp_date = datetime.fromisoformat(cert_data["fecha_caducidad"])
            issue_date = datetime.fromisoformat(cert_data["fecha_expedicion"])

            self.log_message(f"Certificado {tipo} cargado correctamente.")
            return user_sk, user_pk, ent_pk, issue_date, exp_date, cert_data
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar certificado {tipo}: {e}")
            self.log_message(f"Error al cargar certificado {tipo}: {e}")
            return None, None, None, None, None, None

    def add_metadata_to_pdf(self, pdf_path, firma, cert_data):
        """Añade la firma y el certificado de autenticación a los metadatos del PDF sin crear una copia."""
        try:
            doc = fitz.open(pdf_path)
            metadata = doc.metadata
            metadata["keywords"] = json.dumps({
                "firma": firma.hex(),
                "certificado_autenticacion": cert_data
            }, separators=(',', ':'))

            doc.set_metadata(metadata)
            doc.save(pdf_path, incremental=True, encryption=0)  # Guardar con incremental=True
            doc.close()

            self.log_message(f"PDF firmado con metadatos guardado en: {pdf_path}")
            messagebox.showinfo("Éxito", f"PDF firmado guardado en: {pdf_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Error al añadir metadatos al PDF: {e}")
            self.log_message(f"Error al añadir metadatos al PDF: {e}")


    def calcular_hash_documento(self, file_path):
        """Calcula el hash SHA-256 del contenido de un documento."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            return hashlib.sha256(data).digest()  # Retorna el hash en bytes
        except Exception as e:
            raise ValueError(f"Error al calcular el hash del documento: {e}")

    def sign_message(self):
        """Firma un documento y permite al usuario renombrarlo antes de guardarlo."""
        try:
                # Cargar certificado de firma
            user_sk, _, _, _, _, cert_firma = self.load_certificate("firmar")
            if not user_sk:
                return

            # Cargar certificado de autenticación
            _, _, _, _, _, cert_auth = self.load_certificate("autenticacion")
            if not cert_auth:
                return

            # -------------------- CALCULAR HASH DE FIRMA PARA CADA CD --------------------
            cert_copy_auth = cert_auth.copy()
            cert_copy_auth.pop("huella_digital", None)
            cert_firma.pop("huella_digital", None)


            # Calcular hashes
            hash_firma_cd = self.calcular_hash_firma(cert_firma)
            hash_auth_cd = self.calcular_hash_firma(cert_copy_auth)

            if hash_firma_cd != hash_auth_cd:
                messagebox.showerror("Error", "Los certificados de firma y autenticación no están asociados.")
                self.log_message("Error: Los certificados de firma y autenticación no coinciden.")
                return  # 🔴 Salir sin continuar la firma

            # -------------------- SELECCIONAR DOCUMENTO PARA FIRMAR --------------------
            file_path = filedialog.askopenfilename(
                title="Seleccionar archivo para firmar",
                filetypes=[("Archivos PDF", "*.pdf")],
            )
            if not file_path:
                return

            # 🔹 **CALCULAR HASH DEL DOCUMENTO**
            hash_documento = self.calcular_hash_documento(file_path)

            self.log_message(f"Hash del documento: {hash_documento.hex()}")
            self.log_message(f"Hash del documento_bytes: {hash_documento}")

            # 🔹 **FIRMAR EL HASH**
            signature = self.sphincs.sign(hash_documento, user_sk)

            # -------------------- PERMITIR RENOMBRAR Y GUARDAR EL DOCUMENTO --------------------
            save_path = filedialog.asksaveasfilename(
                title="Guardar documento firmado",
                initialfile="documento_firmado.pdf",
                defaultextension=".pdf",
                filetypes=[("Archivos PDF", "*.pdf")],
            )

            if not save_path:
                messagebox.showinfo("Cancelado", "Firma cancelada, no se ha guardado el archivo.")
                return

            # 🔹 **GUARDAR EL ARCHIVO ANTES DE MODIFICARLO**
            with open(save_path, "wb") as f:
                with open(file_path, "rb") as original_file:
                    f.write(original_file.read())  # Copiar el contenido original

            # -------------------- AÑADIR METADATOS AL PDF --------------------
            self.add_metadata_to_pdf(save_path, signature, cert_auth)

        except Exception as e:
            messagebox.showerror("Error", f"Error al firmar documento: {e}")
            self.log_message(f"Error al firmar documento: {e}")


    def verify_signature(self):
        """Verifica la firma de un documento firmado con Sphincs+."""
        try:
            # -------------------- SELECCIONAR DOCUMENTO FIRMADO --------------------
            file_path = filedialog.askopenfilename(
                title="Seleccionar documento firmado",
                filetypes=[("Archivos PDF", "*.pdf")],
            )
            if not file_path:
                return

            # -------------------- EXTRAER METADATOS DEL DOCUMENTO --------------------
            doc = fitz.open(file_path)
            metadata = doc.metadata
            doc.close()

            if "keywords" not in metadata:
                raise ValueError("El documento no contiene metadatos de firma.")

            try:
                metadata_content = json.loads(metadata["keywords"])
                firma_hex = metadata_content.get("firma")
                cert_data = metadata_content.get("certificado_autenticacion")

                if not firma_hex or not cert_data:
                    raise ValueError("El documento firmado no contiene los datos necesarios para la verificación.")
                
                firma_bytes = bytes.fromhex(firma_hex)

            except json.JSONDecodeError:
                raise ValueError("Los metadatos del documento no están en un formato válido.")

            # -------------------- VALIDAR CERTIFICADO DEL USUARIO --------------------
            if not self.verificar_certificado(cert_data):
                raise ValueError("El certificado del documento firmado no es válido.")

            # -------------------- OBTENER PK DEL USUARIO DESDE EL CERTIFICADO --------------------
            user_pk = bytes.fromhex(cert_data["user_public_key"])

            # -------------------- EXTRAER DATOS DEL DOCUMENTO PARA VERIFICAR FIRMA --------------------
            with open(file_path, "rb") as f:
                data = f.read()

            # -------------------- VERIFICAR FIRMA --------------------
            is_valid = self.sphincs.verify(data, firma_bytes, user_pk)

            if is_valid:
                messagebox.showinfo("Verificación", "La firma es válida.")
                self.log_message("✅ Verificación exitosa: La firma es válida.")
            else:
                messagebox.showwarning("Verificación", "La firma no es válida.")
                self.log_message("⚠️ La firma no es válida.")

        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar la firma: {e}")
            self.log_message(f"❌ Error al verificar la firma: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AutoFirmaApp(root)
    root.mainloop()
