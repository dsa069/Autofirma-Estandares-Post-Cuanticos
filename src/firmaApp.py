import sys
import os

# Añadir la carpeta padre (donde está 'package') a sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)  # Subir un nivel desde 'src'
sys.path.insert(0, parent_dir)

import json
import hashlib
import tkinter as tk
from Crypto.Cipher import AES
import base64
from tkinter import messagebox, filedialog, simpledialog
from datetime import datetime
import fitz  # PyMuPDF para manejar metadatos en PDFs
from package.sphincs import Sphincs  # Importar la clase Sphincs
from dilithium_py.ml_dsa import ML_DSA_65  # Usamos ML_DSA_65 (Dilithium3)


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

        ordered_keys_firma = ["nombre", "dni", "fecha_expedicion", "fecha_caducidad", "user_public_key", "entity_public_key", "algoritmo"]
        ordered_data_firma = {key: cert_copy[key] for key in ordered_keys_firma}

        serialized_data_firma = json.dumps(ordered_data_firma, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(serialized_data_firma.encode()).digest()
    
    def verificar_certificado(self, cert_data):
        """Verifica la validez de un certificado (SPHINCS+ o Dilithium)."""
        try:
            # Detectar algoritmo del certificado
            algoritmo = cert_data.get("algoritmo")  # Por defecto SPHINCS+ para compatibilidad
            self.log_message(f"Verificando certificado con algoritmo: {algoritmo.upper()}")
            
            expected_hash = cert_data.get("huella_digital")
            firma = cert_data.get("firma")

            # -------------------- VALIDACIÓN HUELLA DIGITAL --------------------
            cert_copy = cert_data.copy()
            cert_copy.pop("huella_digital", None)

            # Campos ordenados para calcular la huella digital (con algoritmo)
            ordered_keys_huella = ["nombre", "dni", "fecha_expedicion", "fecha_caducidad", 
                                "user_public_key", "entity_public_key", "algoritmo", 
                                "firma", "user_secret_key"]
            ordered_data_huella = {key: cert_copy[key] for key in ordered_keys_huella if key in cert_copy}

            serialized_data_huella = json.dumps(ordered_data_huella, separators=(",", ":"), ensure_ascii=False)
            recalculated_hash = hashlib.sha256(serialized_data_huella.encode()).hexdigest()

            #self.log_message(f"Hash recalculado: {recalculated_hash}")
            # Guardar en archivo para depuración
            #with open("serializado_huella.json", "w", encoding="utf-8") as f:
            #    f.write(serialized_data_huella)

            if recalculated_hash != expected_hash:
                raise ValueError("La huella digital del certificado no es válida.")
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
            if getattr(sys, 'frozen', False):
                BASE_DIR = sys._MEIPASS  # Carpeta temporal de PyInstaller
            else:
                BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Carpeta actual del script
            pk_entidad_path = os.path.join(BASE_DIR, "pk_entidad.json")
            
            if not os.path.exists(pk_entidad_path):
                raise ValueError("No se encontró la clave pública de la entidad.")

            # Leer el archivo de claves públicas según el algoritmo del certificado
            with open(pk_entidad_path, "r") as pk_file:
                pk_data = json.load(pk_file)

                if algoritmo.lower() == "sphincs":
                    # Para certificados SPHINCS+
                    ent_pk_real = bytes.fromhex(pk_data["sphincs_pk"])
                elif algoritmo.lower() == "dilithium":
                    # Para certificados Dilithium
                    ent_pk_real = bytes.fromhex(pk_data["dilithium_pk"])
                else:
                    raise ValueError(f"Algoritmo no reconocido: {algoritmo}")
                
            if ent_pk_cert != ent_pk_real:
                raise ValueError("La clave pública de la entidad en el certificado no coincide con la clave pública oficial.")

            # -------------------- VALIDACIÓN FIRMA --------------------
            recalculated_hash_firma = self.calcular_hash_firma(cert_copy)
            
            #self.log_message(f"Hash recalculado para firma: {recalculated_hash_firma}")

            # Guardar en archivo para depuración
            #with open("serializado_verificacion_firma.json", "w", encoding="utf-8") as f:
            #   f.write(serialized_data_firma)

            # Convertir la firma a bytes
            firma_bytes = bytes.fromhex(firma)
            
            # Verificar firma según el algoritmo usado
            if algoritmo.lower() == "sphincs":
                # Utilizar SPHINCS+ para verificar
                firma_valida = self.sphincs.verify(recalculated_hash_firma, firma_bytes, ent_pk_real)
            elif algoritmo.lower() == "dilithium":
                # Utilizar Dilithium para verificar
                # Nota: ML_DSA_65 usa un orden diferente de parámetros: verify(pk, msg, sig)
                firma_valida = ML_DSA_65.verify(ent_pk_real, recalculated_hash_firma, firma_bytes)
            else:
                raise ValueError(f"Algoritmo no soportado para verificación: {algoritmo}")

            if not firma_valida:
                raise ValueError("La firma del certificado no es válida.")

            return True
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar certificado: {e}")
            self.log_message(f"Error al verificar certificado: {e}")
            return False
        
    def decrypt_private_key(self, encrypted_sk, password):
        """Descifra la clave privada utilizando AES-256 CBC y verifica la redundancia."""
        try:
            encrypted_data = base64.b64decode(encrypted_sk)  # Decodificar de Base64

            # Extraer SALT (primeros 16 bytes)
            salt = encrypted_data[:16]
            
            # Extraer IV (siguientes 16 bytes)
            iv = encrypted_data[16:32]
            
            # Derivar clave con el salt
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
            
            cipher = AES.new(key, AES.MODE_CBC, iv)  # Crear cifrador AES-CBC

            decrypted_sk = cipher.decrypt(encrypted_data[32:])  # Desencriptar
            decrypted_sk = decrypted_sk[:-decrypted_sk[-1]]  # Eliminar padding PKCS7

            # Verificar redundancia (últimos 50 bits = 7 bytes deben repetirse al final)
            if decrypted_sk[-7:] != decrypted_sk[-14:-7]:
                raise ValueError("Contraseña incorrecta: No se validó la redundancia.")

            return decrypted_sk[:-7]  # Devolver clave privada sin redundancia

        except Exception:
            return None  # Error → Contraseña incorrecta
        
    def enviar_alerta_certificado(self, nombre, dni):
        """Muestra una alerta simple en la consola cuando hay intentos fallidos."""
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] ALERTA: Intentos fallidos para {nombre} ({dni})")
        print("-" * 50)
        
        return True
                
    def load_certificate(self, tipo):
        """Carga el certificado del usuario según el tipo ('firmar' o 'autenticacion')."""
        try:
            # Comprobar si existe la carpeta certificados_postC
            user_home = os.path.expanduser("~")
            certs_folder = os.path.join(user_home, "certificados_postC")
            
            # Verificar si la carpeta existe
            if not os.path.exists(certs_folder):
                messagebox.showerror("Error", "No se encuentra la carpeta certificados_postC en su directorio de usuario.")
                self.log_message("Error: No se encuentra la carpeta certificados_postC")
                return None, None, None, None, None, None
                
            cert_path = filedialog.askopenfilename(
                title="Seleccionar certificado",
                initialdir=certs_folder,
                filetypes=[("Certificados", f"certificado_digital_{tipo}_*.json")]
            )
            if not cert_path:
                return None, None, None, None, None, None

            with open(cert_path, "r") as cert_file:
                cert_data = json.load(cert_file)

            if not self.verificar_certificado(cert_data):
                return None, None, None, None, None, None

            user_pk = bytes.fromhex(cert_data["user_public_key"])
            ent_pk = bytes.fromhex(cert_data["entity_public_key"])
            exp_date = datetime.fromisoformat(cert_data["fecha_caducidad"])
            issue_date = datetime.fromisoformat(cert_data["fecha_expedicion"])
            user_sk = None

            if tipo == "firmar":
                encrypted_sk = cert_data.get("user_secret_key")
                if not encrypted_sk:
                    raise ValueError("No se encontró la clave privada cifrada en el certificado.")

                intento = 0
                while True:  # Bucle infinito hasta que se introduzca la contraseña correcta

                    password = simpledialog.askstring(
                        "Contraseña", "Introduce la contraseña del certificado:", show="*"
                    )

                    if not password:
                        return None, None, None, None, None, None  # Usuario canceló

                    user_sk = self.decrypt_private_key(encrypted_sk, password)

                    if user_sk:
                        break  # Clave descifrada correctamente
                    else:
                        messagebox.showerror("Error", "Contraseña incorrecta. Inténtalo de nuevo.")
                        intento += 1
                        if intento == 3:  # Mostrar alerta cada 3 intentos
                            self.enviar_alerta_certificado(cert_data["nombre"], cert_data["dni"])

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
            fecha_firma = datetime.now().isoformat()
            metadata["keywords"] = json.dumps({
                "firma": firma.hex(),
                "certificado_autenticacion": cert_data,
                "fecha_firma": fecha_firma
            }, separators=(',', ':'))

            doc.set_metadata(metadata)
            doc.save(pdf_path, incremental=True, encryption=0)  # Guardar con incremental=True
            doc.close()

            self.log_message(f"PDF firmado con metadatos guardado en: {pdf_path}")
            messagebox.showinfo("Éxito", f"PDF firmado guardado en: {pdf_path}\nFecha de firma: {fecha_firma}")

        except Exception as e:
            messagebox.showerror("Error", f"Error al añadir metadatos al PDF: {e}")
            self.log_message(f"Error al añadir metadatos al PDF: {e}")


    def calcular_hash_documento(self, file_path):
        """Calcula el hash SHA-256 del contenido del documento, ignorando los metadatos."""
        try:
            doc = fitz.open(file_path)

            # Extraer solo los bytes de las páginas, ignorando metadatos
            contenido_binario = b"".join(doc[page].get_text("text").encode() for page in range(len(doc)))

            doc.close()
            
            return hashlib.sha256(contenido_binario).digest()
        
        except Exception as e:
            raise ValueError(f"Error al calcular el hash del documento: {e}")
        
    def add_written_signature(self, pdf_path, nombre_certificado):
        """Ventana unificada para seleccionar página y posición de firma."""
        try:
            # Abrir el documento PDF
            doc = fitz.open(pdf_path)
            total_pages = len(doc)
            
            # Definir tamaño de la firma
            signature_width = 175
            signature_height = 30
            
            # Crear ventana para seleccionar posición
            signature_window = tk.Toplevel(self.root)
            signature_window.title("Selección de página y posición")
            signature_window.geometry("800x700")
            signature_window.resizable(True, True)
            signature_window.transient(self.root)
            signature_window.grab_set()
            
            # Variables para almacenar la posición seleccionada
            selected_x = tk.IntVar(value=0)
            selected_y = tk.IntVar(value=0)
            
            # Variable para controlar la página actual
            current_page = tk.IntVar(value=1)
            
            # Variable para almacenar el rectángulo de previsualización
            signature_rect = [None]
            
            # Almacenar referencia a la imagen mostrada
            preview_image = [None]
            
            # Almacenar dimensiones de la página actual
            page_dimensions = [0, 0]
            
            # Almacenar offset para centrado
            offset_x = [0]
            offset_y = [0]
            
            # Variable para los resultados
            result = {"success": False, "page": 0, "position": (0, 0)}
            
            # Definir funciones antes de crear widgets que las referencian
            def update_preview():
                # Obtener número de página (base 0)
                page_num = int(current_page.get()) - 1
                if page_num < 0:
                    page_num = 0
                    current_page.set(1)
                elif page_num >= total_pages:
                    page_num = total_pages - 1
                    current_page.set(total_pages)
                
                # Limpiar canvas y eliminar rectángulo previo
                canvas.delete("all")
                if signature_rect[0]:
                    signature_rect[0] = None
                
                # Renderizar página con escala de 0.8
                pix = doc[page_num].get_pixmap(matrix=fitz.Matrix(0.8, 0.8))
                img_data = pix.tobytes("ppm")
                
                # Convertir a imagen de Tkinter
                from PIL import Image, ImageTk
                import io
                img = Image.open(io.BytesIO(img_data))
                img_tk = ImageTk.PhotoImage(img)
                
                # Guardar dimensiones de la página escalada
                page_dimensions[0] = img.width
                page_dimensions[1] = img.height
                
                # Mantener referencia a la imagen
                preview_image[0] = img_tk
                
                # Calcular posición para centrar la imagen
                canvas_width = preview_frame.winfo_width()
                canvas_height = preview_frame.winfo_height()
                
                # Si el frame aún no tiene tamaño (primera carga), usar tamaños predeterminados
                if canvas_width <= 1:
                    canvas_width = 780  # Ancho aproximado del canvas
                if canvas_height <= 1:
                    canvas_height = 500  # Alto aproximado del canvas
                
                # Ajustar tamaño del canvas al tamaño de la imagen o del frame, lo que sea menor
                canvas.config(width=canvas_width, height=canvas_height)
                
                # Calcular offset para centrar
                offset_x[0] = max(0, (canvas_width - img.width) // 2)
                offset_y[0] = max(0, (canvas_height - img.height) // 2)
                
                # Mostrar la imagen en el canvas centrada
                canvas.create_image(offset_x[0], offset_y[0], anchor=tk.NW, image=img_tk)
                
                # Dibujar un borde alrededor del documento para mejor visualización
                canvas.create_rectangle(
                    offset_x[0], offset_y[0], 
                    offset_x[0] + img.width, offset_y[0] + img.height,
                    outline="gray", width=1
                )
                
                # Resetear posición seleccionada
                selected_x.set(0)
                selected_y.set(0)
                position_label.config(text="Posición: No seleccionada")
            
            def change_page(delta):
                new_page = current_page.get() + delta
                if 1 <= new_page <= total_pages:
                    current_page.set(new_page)
                    update_preview()
                    
            def on_canvas_click(event):
                # Obtener coordenadas del canvas
                x = event.x
                y = event.y
                
                # Ajustar por el offset de centrado
                x_adjusted = x - offset_x[0]
                y_adjusted = y - offset_y[0]
                
                # Verificar si el clic está dentro de los límites del documento
                if (x_adjusted < 0 or y_adjusted < 0 or 
                    x_adjusted >= page_dimensions[0] or y_adjusted >= page_dimensions[1]):
                    return  # Ignorar clics fuera del documento
                
                # Convertir coordenadas del canvas a coordenadas del documento real
                real_x = x_adjusted / 0.8  # Ajustar por la escala
                real_y = y_adjusted / 0.8  # Ajustar por la escala
                
                # Actualizar variables - estas son las coordenadas exactas de la esquina superior izquierda
                selected_x.set(int(real_x - signature_width/2))
                selected_y.set(int(real_y - signature_height/2))
                
                # Actualizar etiqueta
                position_label.config(text=f"Posición: ({selected_x.get()}, {selected_y.get()})")
                
                # Eliminar rectángulo anterior si existe
                if signature_rect[0]:
                    canvas.delete(signature_rect[0])
                
                # Dibujar rectángulo en la posición seleccionada
                rect_x = x_adjusted - (signature_width * 0.8) / 2
                rect_y = y_adjusted - (signature_height * 0.8) / 2
                
                signature_rect[0] = canvas.create_rectangle(
                    rect_x + offset_x[0], rect_y + offset_y[0], 
                    rect_x + (signature_width * 0.8) + offset_x[0], 
                    rect_y + (signature_height * 0.8) + offset_y[0],
                    outline="black", width=2
                )
                    
            def on_accept():
                if selected_x.get() == 0 and selected_y.get() == 0:
                    messagebox.showwarning("Aviso", "Por favor, seleccione una posición haciendo clic en la página.")
                    return
                
                result["success"] = True
                result["page"] = int(current_page.get()) - 1
                result["position"] = (selected_x.get(), selected_y.get())
                signature_window.destroy()
            
            def on_cancel():
                signature_window.destroy()
            
            # CAMBIO: Primero crear el panel de previsualización
            # Panel principal con altura fija para mostrar la página y seleccionar posición
            preview_frame = tk.Frame(signature_window, height=500)
            preview_frame.pack(fill=tk.X, padx=10, pady=10)
            preview_frame.pack_propagate(False)  # Evitar que el frame cambie de tamaño
            
            # Canvas con tamaño fijo para mostrar la página
            canvas = tk.Canvas(preview_frame, bg="#f0f0f0", width=780, height=500)
            canvas.pack(expand=True)
            
            # Vincular evento de clic
            canvas.bind("<Button-1>", on_canvas_click)
            
            # CAMBIO: Ahora crear el selector de página DESPUÉS de la previsualización
            page_frame_container = tk.Frame(signature_window)
            page_frame_container.pack(fill=tk.X, pady=10)
            
            page_frame = tk.Frame(page_frame_container)
            page_frame.pack(side=tk.TOP, pady=5)
            
            # Etiqueta y selector de página
            tk.Label(page_frame, text="Página:", font=("Arial", 11)).pack(side=tk.LEFT, padx=5)
            
            # Botón página anterior
            prev_btn = tk.Button(page_frame, text="◀", command=lambda: change_page(-1))
            prev_btn.pack(side=tk.LEFT, padx=5)
            
            # Entry para seleccionar página
            page_entry = tk.Entry(page_frame, textvariable=current_page, width=3, justify=tk.CENTER)
            page_entry.pack(side=tk.LEFT, padx=5)
            
            # Validación para la entrada de página
            def validate_page(event=None):
                try:
                    page = int(current_page.get())
                    if page < 1:
                        current_page.set(1)
                    elif page > total_pages:
                        current_page.set(total_pages)
                    update_preview()
                except ValueError:
                    current_page.set(1)
                    update_preview()
            
            page_entry.bind("<Return>", validate_page)
            page_entry.bind("<FocusOut>", validate_page)
            
            # Botón página siguiente
            next_btn = tk.Button(page_frame, text="▶", command=lambda: change_page(1))
            next_btn.pack(side=tk.LEFT, padx=5)
            
            # Etiqueta de total de páginas
            tk.Label(page_frame, text=f"de {total_pages}", font=("Arial", 11)).pack(side=tk.LEFT, padx=5)
            
            # Panel inferior para instrucciones y botones
            instruction_frame = tk.Frame(signature_window)
            instruction_frame.pack(fill=tk.X, pady=10)
            
            # Instrucciones
            instruction_label = tk.Label(instruction_frame, 
                                    text="Haga clic en la página donde desea ubicar la firma",
                                    font=("Arial", 10))
            instruction_label.pack(pady=5)
            
            # Etiqueta para mostrar la posición seleccionada
            position_label = tk.Label(instruction_frame, text="Posición: No seleccionada")
            position_label.pack(pady=5)
            
            # Botones de acción
            button_frame = tk.Frame(signature_window)
            button_frame.pack(pady=10)
            
            # Botones de aceptar/cancelar
            tk.Button(button_frame, text="Aceptar", command=on_accept, width=10).pack(side=tk.LEFT, padx=20)
            tk.Button(button_frame, text="Cancelar", command=on_cancel, width=10).pack(side=tk.RIGHT, padx=20)
            
            # Mostrar vista previa inicial después de crear el canvas
            signature_window.update()
            update_preview()
            
            # Esperar a que se cierre la ventana
            self.root.wait_window(signature_window)
            
            # Resto del código igual que antes para añadir la firma al PDF
            if not result["success"]:
                return False
                
            # Añadir la firma visual al PDF
            try:
                doc = fitz.open(pdf_path)
                page = doc[result["page"]]
                x, y = result["position"]
                rect = fitz.Rect(x, y, x + signature_width, y + signature_height)
                
                signature_text = f"Firmado digitalmente por: {nombre_certificado}"
                signature_date = f"Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"
                
                # Firma en blanco y negro
                page.draw_rect(rect, color=(0, 0, 0), fill=(1, 1, 1), width=1, overlay=True)  # Fondo blanco, borde negro
                
                text_point = fitz.Point(x + 5, y + 15)
                page.insert_text(text_point, signature_text, fontsize=8, color=(0, 0, 0), overlay=True)  # Texto negro
                
                text_point = fitz.Point(x + 5, y + 25)
                page.insert_text(text_point, signature_date, fontsize=8, color=(0, 0, 0), overlay=True)  # Texto negro
                
                doc.save(pdf_path, incremental=True, encryption=0)
                doc.close()
                
                self.log_message(f"Firma visual añadida en la página {result['page']+1}")
                return True
                
            except Exception as e:
                self.log_message(f"Error al añadir firma visual: {e}")
                return False
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al seleccionar posición: {e}")
            self.log_message(f"Error al seleccionar posición: {e}")
            return False

    def sign_message(self):
        """Firma un documento digitalmente y permite añadir una firma escrita opcional en el PDF."""
        try:
            # Cargar certificado de firma
            user_sk, _, _, _, _, cert_firma = self.load_certificate("firmar")
            if not user_sk:
                return

            # Extraer DNI y algoritmo del certificado de firma
            dni = cert_firma["dni"]
            algoritmo = cert_firma["algoritmo"].lower()
            
            # Buscar automáticamente el certificado de autenticación correspondiente
            user_home = os.path.expanduser("~")
            certs_folder = os.path.join(user_home, "certificados_postC")
            cert_auth_path = os.path.join(certs_folder, f"certificado_digital_autenticacion_{dni}_{algoritmo}.json")
            
            # Verificar si existe el certificado de autenticación
            if not os.path.exists(cert_auth_path):
                messagebox.showerror("Error", f"No se encontró el certificado de autenticación para el DNI {dni}.")
                self.log_message(f"Error: No se encontró certificado de autenticación para DNI {dni}")
                return
                
            # Cargar el certificado de autenticación
            try:
                with open(cert_auth_path, "r") as cert_file:
                    cert_auth = json.load(cert_file)
                    
                # Verificar el certificado de autenticación
                if not self.verificar_certificado(cert_auth):
                    messagebox.showerror("Error", "El certificado de autenticación no es válido.")
                    self.log_message("Error: Certificado de autenticación inválido.")
                    return
                    
                self.log_message(f"Certificado de autenticación cargado automáticamente para DNI: {dni}")
            except Exception as e:
                messagebox.showerror("Error", f"Error al cargar certificado de autenticación: {e}")
                self.log_message(f"Error al cargar certificado de autenticación: {e}")
                return

            # OBTENER EL NOMBRE DEL CERTIFICADO DE FIRMA
            nombre_certificado = cert_firma["nombre"]

            # CALCULAR HASH DE LOS CERTIFICADOS
            cert_copy_auth = cert_auth.copy()
            cert_copy_auth.pop("huella_digital", None)
            cert_firma.pop("huella_digital", None)

            hash_firma_cd = self.calcular_hash_firma(cert_firma)
            hash_auth_cd = self.calcular_hash_firma(cert_copy_auth)

            if hash_firma_cd != hash_auth_cd:
                messagebox.showerror("Error", "Los certificados de firma y autenticación no están asociados.")
                self.log_message("Error: Los certificados de firma y autenticación no coinciden.")
                return

            # SELECCIONAR DOCUMENTO PARA FIRMAR
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            file_path = filedialog.askopenfilename(
                title="Seleccionar archivo para firmar",
                initialdir=desktop_path,  # Usar el Escritorio como carpeta inicial
                filetypes=[("Archivos PDF", "*.pdf")],
            )
            if not file_path:
                return

            # PERMITIR RENOMBRAR Y GUARDAR EL DOCUMENTO
            save_path = filedialog.asksaveasfilename(
                title="Guardar documento firmado",
                initialfile="documento_firmado.pdf",
                defaultextension=".pdf",
                filetypes=[("Archivos PDF", "*.pdf")],
            )

            if not save_path:
                messagebox.showinfo("Cancelado", "Firma cancelada, no se ha guardado el archivo.")
                return

            # GUARDAR EL DOCUMENTO FIRMADO DIGITALMENTE
            with open(save_path, "wb") as f:
                with open(file_path, "rb") as original_file:
                    f.write(original_file.read())  # Copiar el contenido original

            # PREGUNTAR AL USUARIO SI DESEA AÑADIR FIRMA ESCRITA
            # IMPORTANTE: Añadir la firma visual ANTES de calcular el hash y firmar digitalmente
            agregar_firma = messagebox.askyesno("Firma Escrita", "¿Desea añadir una firma escrita en el PDF?")
            if agregar_firma:
                if not self.add_written_signature(save_path, nombre_certificado):
                    # Si se cancela la firma escrita, seguimos con la firma digital normal
                    self.log_message("Firma escrita cancelada, continuando con firma digital.")

            # CALCULAR HASH DEL DOCUMENTO (después de añadir la firma escrita si se solicitó)
            hash_documento = self.calcular_hash_documento(save_path)
            self.log_message(f"Hash del documento: {hash_documento.hex()}")

            # OBTENER EL ALGORITMO DEL CERTIFICADO
            algoritmo = cert_firma.get("algoritmo", "sphincs").lower()
            self.log_message(f"Firmando con algoritmo: {algoritmo.upper()}")

            # FIRMAR EL HASH DIGITALMENTE SEGÚN EL ALGORITMO
            if algoritmo == "sphincs":
                # Firmar con SPHINCS+
                signature = self.sphincs.sign(hash_documento, user_sk)
            elif algoritmo == "dilithium":
                # Firmar con Dilithium (orden diferente de parámetros)
                signature = ML_DSA_65.sign(user_sk, hash_documento)
            else:
                raise ValueError(f"Algoritmo no soportado para firma: {algoritmo}")

            # AÑADIR METADATOS AL PDF (incluida la firma digital)
            self.add_metadata_to_pdf(save_path, signature, cert_auth)

            messagebox.showinfo("Éxito", f"Documento firmado correctamente y guardado en:\n{save_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Error al firmar documento: {e}")
            self.log_message(f"Error al firmar documento: {e}")

    def verify_signature(self):
        """Verifica una firma utilizando el hash del documento calculado en tiempo real."""
        try:
            # -------------------- SELECCIONAR DOCUMENTO FIRMADO --------------------
            file_path = filedialog.askopenfilename(
                title="Seleccionar archivo firmado",
                filetypes=[("Archivos PDF", "*.pdf")],
            )
            if not file_path:
                return

            # **EXTRAER METADATOS DEL PDF**
            doc = fitz.open(file_path)
            metadata = doc.metadata
            doc.close()

            # **EXTRAER FIRMA Y CERTIFICADO**
            try:
                meta_data = json.loads(metadata.get("keywords", "{}"))
                firma = bytes.fromhex(meta_data["firma"])
                cert_data = meta_data["certificado_autenticacion"]
            except Exception:
                messagebox.showerror("Error", "No se encontraron metadatos de firma en el documento.")
                return

            # 🔹 **VALIDAR EL CERTIFICADO**
            if not self.verificar_certificado(cert_data):
                messagebox.showerror("Error", "El certificado en el documento firmado no es válido.")
                return

            # **OBTENER LA CLAVE PÚBLICA DEL USUARIO DESDE EL CERTIFICADO Y ALGORITMO**
            user_pk = bytes.fromhex(cert_data["user_public_key"])
            algoritmo = cert_data.get("algoritmo").lower()  # Default a Sphincs para compatibilidad

            # **CALCULAR EL HASH DEL DOCUMENTO ACTUAL**
            hash_documento_actual = self.calcular_hash_documento(file_path)

            #self.log_message(f"Hash del documento: {hash_documento_actual.hex()}")
            #self.log_message(f"Hash del documento_bytes: {hash_documento_actual}")

            # **VERIFICAR LA FIRMA**
            # **VERIFICAR LA FIRMA SEGÚN EL ALGORITMO**
            if algoritmo == "sphincs":
                # Verificar con SPHINCS+
                is_valid = self.sphincs.verify(hash_documento_actual, firma, user_pk)
            elif algoritmo == "dilithium":
                # Verificar con Dilithium (orden diferente de parámetros)
                is_valid = ML_DSA_65.verify(user_pk, hash_documento_actual, firma)
            else:
                messagebox.showerror("Error", f"Algoritmo desconocido: {algoritmo}")
                self.log_message(f"Error: Algoritmo desconocido: {algoritmo}")
                return
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
