import ctypes
import sys
import os
from backend.funcComunes import log_message, calcular_hash_firma, calcular_hash_huella, init_paths

BASE_DIR = init_paths()

import json
import hashlib
import tkinter as tk
from Crypto.Cipher import AES
import base64
from tkinter import PhotoImage, messagebox, filedialog, simpledialog
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
        # 🔹 Rutas del icono
        if getattr(sys, 'frozen', False):
            # Ejecutando como archivo compilado
            ruta_icono = os.path.join(BASE_DIR, "Diego.ico")
            ruta_icono_png = os.path.join(BASE_DIR, "Diego.png")
        else:
            # Ejecutando como script Python
            ruta_icono = os.path.join(os.path.dirname(os.path.abspath(__file__)), "img", "Diego.ico")
            ruta_icono_png = os.path.join(os.path.dirname(os.path.abspath(__file__)), "img", "Diego.png")
        # 🔹 Asegurar que Windows asocia la aplicación correctamente a la barra de tareas
        myappid = 'miapp.certificadosdigitales'  # Nombre único
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

        # 🔹 (TRUCO) Crear ventana oculta para forzar el icono en la barra de tareas
        self.ventana_oculta = tk.Toplevel()
        self.ventana_oculta.withdraw()  # Oculta la ventana

        # 🔹 Intentar establecer el icono .ico
        if os.path.exists(ruta_icono):
            self.root.iconbitmap(ruta_icono)  # Icono en la cabecera
            self.ventana_oculta.iconbitmap(ruta_icono)  # Forzar icono en barra de tareas
        else:
            messagebox.showwarning("Advertencia", "⚠️ Icono .ico no encontrado, verifica la ruta.")

        # 🔹 Intentar establecer el icono .png en la barra de tareas
        if os.path.exists(ruta_icono_png):
            icono = PhotoImage(file=ruta_icono_png)
            self.root.iconphoto(True, icono)  # Icono en la barra de tareas
        else:
            messagebox.showwarning("Advertencia", "⚠️ Icono .png no encontrado, verifica la ruta.")

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

    def calcular_hash_firma(self, cert_copy):
        cert_copy.pop("firma", None)
        cert_copy.pop("user_secret_key", None)  # No debe estar en la firma

        return calcular_hash_firma(cert_copy)
    
    def verificar_certificado(self, cert_data):
        """Verifica la validez de un certificado (SPHINCS+ o Dilithium)."""
        try:
            # Detectar algoritmo del certificado
            algoritmo = cert_data.get("algoritmo")  # Por defecto SPHINCS+ para compatibilidad
            log_message("firmaApp.log",f"Verificando certificado con algoritmo: {algoritmo.upper()}")
            
            expected_hash = cert_data.get("huella_digital")
            firma = cert_data.get("firma")

            # -------------------- VALIDACIÓN HUELLA DIGITAL --------------------
            cert_copy = cert_data.copy()
            cert_copy.pop("huella_digital", None)

            if calcular_hash_huella(cert_copy) != expected_hash:
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
                raise ValueError("No se encontró el archivo de claves públicas de la entidad.")

            # Leer el archivo de claves públicas de la entidad (ahora contiene una lista de objetos)
            with open(pk_entidad_path, "r") as pk_file:
                pk_data_list = json.load(pk_file)
                
                # Verificar que el archivo contiene datos
                if not pk_data_list or not isinstance(pk_data_list, list):
                    raise ValueError("El archivo de claves públicas está vacío o no tiene el formato esperado.")
                
                # Filtrar las claves que coinciden con el algoritmo del certificado
                algoritmo_lower = algoritmo.lower()
                claves_algoritmo = [pk for pk in pk_data_list if pk.get("algoritmo", "").lower() == algoritmo_lower]
                
                if not claves_algoritmo:
                    raise ValueError(f"No se encontraron claves públicas para el algoritmo {algoritmo}.")
                
                # Comprobar si la clave del certificado coincide con alguna de las claves almacenadas
                clave_encontrada = False
                for pk_entry in claves_algoritmo:
                    try:
                        ent_pk_candidata = bytes.fromhex(pk_entry.get("clave", ""))
                        if ent_pk_cert == ent_pk_candidata:
                            clave_encontrada = True
                            log_message("firmaApp.log",f"Clave pública de entidad verificada: {pk_entry.get('titulo', 'Sin título')}")
                            break
                    except Exception as e:
                        log_message("firmaApp.log",f"Error al procesar clave candidata: {e}")
                
                if not clave_encontrada:
                    raise ValueError("La clave pública de la entidad en el certificado no coincide con ninguna clave oficial.")
                
            # -------------------- VALIDACIÓN FIRMA --------------------
            recalculated_hash_firma = self.calcular_hash_firma(cert_copy)

            # Convertir la firma a bytes
            firma_bytes = bytes.fromhex(firma)
            
            # Verificar firma según el algoritmo usado
            if algoritmo.lower() == "sphincs":
                # Utilizar SPHINCS+ para verificar
                firma_valida = self.sphincs.verify(recalculated_hash_firma, firma_bytes, ent_pk_cert)
            elif algoritmo.lower() == "dilithium":
                # Utilizar Dilithium para verificar
                # Nota: ML_DSA_65 usa un orden diferente de parámetros: verify(pk, msg, sig)
                firma_valida = ML_DSA_65.verify(ent_pk_cert, recalculated_hash_firma, firma_bytes)
            else:
                raise ValueError(f"Algoritmo no soportado para verificación: {algoritmo}")

            if not firma_valida:
                raise ValueError("La firma del certificado no es válida.")

            return True
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar certificado: {e}")
            log_message("firmaApp.log",f"Error al verificar certificado: {e}")
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
        log_message("firmaApp.log",f"[{timestamp}] ALERTA: Intentos fallidos para {nombre} ({dni})")
        log_message("firmaApp.log","-" * 50)
        
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
                log_message("firmaApp.log","Error: No se encuentra la carpeta certificados_postC")
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

            log_message("firmaApp.log",f"Certificado {tipo} cargado correctamente.")
            return user_sk, user_pk, ent_pk, issue_date, exp_date, cert_data
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar certificado {tipo}: {e}")
            log_message("firmaApp.log",f"Error al cargar certificado {tipo}: {e}")
            return None, None, None, None, None, None

    def add_metadata_to_pdf(self, pdf_path, firma, cert_data, visual_signature_hash=None):
        """Añade la firma y el certificado de autenticación a los metadatos del PDF preservando firmas anteriores."""
        try:
            doc = fitz.open(pdf_path)
            metadata = doc.metadata
            fecha_firma = datetime.now().isoformat()
            
            # Nueva entrada de firma
            nueva_firma = {
                "firma": firma.hex(),
                "certificado_autenticacion": cert_data,
                "fecha_firma": fecha_firma
            }

            # Añadir el hash de la firma visual si existe
            if visual_signature_hash:
                nueva_firma["hash_visual_signature"] = visual_signature_hash.hex()
            
            # Verificar si ya existen metadatos de firmas
            existing_metadata = {}
            if "keywords" in metadata and metadata["keywords"]:
                try:
                    existing_metadata = json.loads(metadata["keywords"])
                except json.JSONDecodeError:
                    existing_metadata = {}
            
            # Verificar si ya existe un array de firmas
            if "firmas" in existing_metadata:
                # Añadir la nueva firma al array existente
                existing_metadata["firmas"].append(nueva_firma)
            else:
                # Crear un nuevo array con la primera firma
                existing_metadata["firmas"] = [nueva_firma]
            
            # Actualizar los metadatos
            metadata["keywords"] = json.dumps(existing_metadata, separators=(',', ':'))
            
            doc.set_metadata(metadata)
            doc.save(pdf_path, incremental=True, encryption=0)
            doc.close()
            
            log_message("firmaApp.log",f"PDF firmado con metadatos guardado en: {pdf_path}")
            messagebox.showinfo("Éxito", f"PDF firmado guardado en: {pdf_path}\nFecha de firma: {fecha_firma}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al añadir metadatos al PDF: {e}")
            log_message("firmaApp.log",f"Error al añadir metadatos al PDF: {e}")


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

            # Guardar el documento antes de añadir la firma visual para calcular el hash "antes"
            doc_before = fitz.open(pdf_path)
            hash_before = self.calcular_hash_documento(pdf_path)
            doc_before.close()

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
                
                # JUSTO AQUÍ: Añadir una anotación click con JavaScript
                try:
                    # Prepare the encoded path and URI 
                    uri = "autofirma://CURRENT_PDF"

                    
                    # Añadir un enlace HTTP que redirige al protocolo personalizado
                    # Esta técnica es mejor aceptada por Chrome
                    html_redirect = f'''
                    <html>
                    <head>
                        <meta http-equiv="refresh" content="0;url={uri}">
                        <title>Redirigiendo a AutoFirma</title>
                    </head>
                    <body>
                        <p>Verificando firma... si no se abre automáticamente, 
                        <a href="{uri}">haga clic aquí</a>.</p>
                    </body>
                    </html>
                    '''
                    
                    # Generar un nombre único para el archivo HTML basado en la ruta del PDF
                    pdf_hash = hashlib.md5(pdf_path.encode()).hexdigest()[:10]
                    pdf_basename = os.path.basename(pdf_path).replace(".", "_")
                    
                    # Guardar la página de redirección en el directorio temporal con nombre único
                    temp_dir = os.path.join(os.path.expanduser("~"), "temp_autofirma")
                    os.makedirs(temp_dir, exist_ok=True)
                    
                    # Usar nombre único para cada redirección
                    redirect_path = os.path.join(temp_dir, f"redirect_{pdf_basename}_{pdf_hash}.html")
                    
                    with open(redirect_path, "w") as f:
                        f.write(html_redirect)
                    
                    # Usar una URL file:// para abrir la página HTML
                    redirect_uri = f"file:///{redirect_path.replace('\\', '/')}"
                    
                    # Insertar el enlace que apunta a la página de redirección
                    page.insert_link({
                        "kind": fitz.LINK_URI,
                        "from": rect,
                        "uri": redirect_uri
                    })
                    
                    log_message("firmaApp.log",f"Firma clickable creada para {os.path.basename(pdf_path)}")
                except Exception as e:
                    log_message("firmaApp.log",f"Error al añadir enlace: {e}")

                doc.save(pdf_path, incremental=True, encryption=0)
                doc.close()

                
                # Calcular el hash "después" de añadir la firma visual
                doc_after = fitz.open(pdf_path)
                hash_after = self.calcular_hash_documento(pdf_path)
                doc_after.close()
                
                # IMPORTANTE: Calcular el hash de la DIFERENCIA entre antes y después
                # Esto representará más precisamente la firma visual por sí sola
                visual_signature_hash = bytes(a ^ b for a, b in zip(hash_before, hash_after))

                
                log_message("firmaApp.log",f"Firma visual añadida en la página {result['page']+1}")
                return True, visual_signature_hash
                
            except Exception as e:
                log_message("firmaApp.log",f"Error al añadir firma visual: {e}")
                return False, None
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al seleccionar posición: {e}")
            log_message("firmaApp.log",f"Error al seleccionar posición: {e}")
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
                log_message("firmaApp.log",f"Error: No se encontró certificado de autenticación para DNI {dni}")
                return
                
            # Cargar el certificado de autenticación
            try:
                with open(cert_auth_path, "r") as cert_file:
                    cert_auth = json.load(cert_file)
                    
                # Verificar el certificado de autenticación
                if not self.verificar_certificado(cert_auth):
                    messagebox.showerror("Error", "El certificado de autenticación no es válido.")
                    log_message("firmaApp.log","Error: Certificado de autenticación inválido.")
                    return
                    
                log_message("firmaApp.log",f"Certificado de autenticación cargado automáticamente para DNI: {dni}")
            except Exception as e:
                messagebox.showerror("Error", f"Error al cargar certificado de autenticación: {e}")
                log_message("firmaApp.log",f"Error al cargar certificado de autenticación: {e}")
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
                log_message("firmaApp.log","Error: Los certificados de firma y autenticación no coinciden.")
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

            visual_signature_hash = None
            
            # PREGUNTAR AL USUARIO SI DESEA AÑADIR FIRMA ESCRITA
            agregar_firma = messagebox.askyesno("Firma Escrita", "¿Desea añadir una firma escrita en el PDF?")
            if agregar_firma:
                success, visual_hash = self.add_written_signature(save_path, nombre_certificado)
                if success:
                    visual_signature_hash = visual_hash
                else:
                    # Si se cancela la firma escrita, seguimos con la firma digital normal
                    log_message("firmaApp.log","Firma escrita cancelada, continuando con firma digital.")

            # CALCULAR HASH DEL DOCUMENTO (después de añadir la firma escrita si se solicitó)
            hash_documento = self.calcular_hash_documento(save_path)
            log_message("firmaApp.log",f"Hash del documento: {hash_documento.hex()}")

            # OBTENER EL ALGORITMO DEL CERTIFICADO
            algoritmo = cert_firma.get("algoritmo", "sphincs").lower()
            log_message("firmaApp.log",f"Firmando con algoritmo: {algoritmo.upper()}")

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
            self.add_metadata_to_pdf(save_path, signature, cert_auth, visual_signature_hash)

            # Registrar en el log el documento firmado
            titulo_doc = os.path.basename(save_path)
            log_message("firmaApp.log",f"Documento firmado: '{titulo_doc}' | Hash: {hash_documento.hex()} | Firmante: {nombre_certificado}")
            messagebox.showinfo("Éxito", f"Documento firmado correctamente y guardado en:\n{save_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Error al firmar documento: {e}")
            log_message("firmaApp.log",f"Error al firmar documento: {e}")

    def verify_signature(self):
        """Verifica todas las firmas en un documento PDF."""
        try:
            # Seleccionar documento firmado
            file_path = filedialog.askopenfilename(
                title="Seleccionar archivo firmado",
                filetypes=[("Archivos PDF", "*.pdf")],
            )
            if not file_path:
                return

            # Extraer metadatos del PDF
            doc = fitz.open(file_path)
            metadata = doc.metadata
            doc.close()

            # Extraer firmas
            try:
                meta_data = json.loads(metadata.get("keywords", "{}"))
                
                # Verificar si hay múltiples firmas o formato antiguo
                firmas = meta_data["firmas"]
                if not firmas:
                    messagebox.showerror("Error", "No se encontraron firmas en el documento.")
                    return
                        
                # Calcular el hash del documento actual (una sola vez para todas las verificaciones)
                hash_documento_actual = self.calcular_hash_documento(file_path)
                
                # Verificar todas las firmas y mostrar resultados
                self.mostrar_resultados_firmas(file_path, firmas, hash_documento_actual)
                    
            except Exception as e:
                messagebox.showerror("Error", f"Error al extraer firmas: {e}")
                log_message("firmaApp.log",f"Error al extraer firmas: {e}")
                return

        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar firmas: {e}")
            log_message("firmaApp.log",f"Error al verificar firmas: {e}")

    def mostrar_resultados_firmas(self, file_path, firmas, hash_documento_actual):
        """Muestra los resultados de la verificación de múltiples firmas en cascada."""
        # Crear ventana de resultados
        results_window = tk.Toplevel(self.root)
        results_window.title(f"Verificación de firmas: {os.path.basename(file_path)}")
        results_window.geometry("800x600")
        results_window.transient(self.root)
        results_window.grab_set()
        
        # Título
        tk.Label(
            results_window, 
            text="Verificación de Firmas Digitales", 
            font=("Arial", 14, "bold")
        ).pack(pady=10)
        
        # Información del documento
        doc_frame = tk.Frame(results_window)
        doc_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(
            doc_frame, 
            text=f"Documento: {os.path.basename(file_path)}", 
            font=("Arial", 10), 
            anchor="w"
        ).pack(fill=tk.X)
        
        # Frame con scroll para resultados
        list_frame = tk.Frame(results_window)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Título para la lista
        tk.Label(
            list_frame, 
            text="Firmas encontradas:", 
            font=("Arial", 11, "bold"),
            anchor="w"
        ).pack(fill=tk.X, pady=(0, 5))
        
        # Crear un frame con scroll para contener los resultados
        canvas = tk.Canvas(list_frame)
        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Inicializar contadores
        valid_count = 0
        invalid_count = 0
        
        # IMPORTANTE: Procesar firmas en orden inverso para la validación en cascada
        total_firmas = len(firmas)
        
        # Inicializar hash actual con el hash del documento completo
        hash_actual = hash_documento_actual
        
        # Lista para almacenar los resultados de validación
        resultados_validacion = []
        
        # FASE 1: Procesar las firmas de la más reciente a la más antigua
        log_message("firmaApp.log","Iniciando verificación en cascada de firmas...")
        for i in range(total_firmas - 1, -1, -1):
            firma_data = firmas[i]
            
            # Extraer datos básicos
            firma = bytes.fromhex(firma_data["firma"])
            cert_data = firma_data["certificado_autenticacion"]
            nombre = cert_data.get("nombre", "Desconocido")
            algoritmo = cert_data.get("algoritmo", "sphincs").lower()
            user_pk = bytes.fromhex(cert_data["user_public_key"])
            
            # Verificar certificado
            cert_valido = self.verificar_certificado(cert_data)
            
            # Verificar firma usando el hash actual
            if cert_valido:
                if algoritmo == "sphincs":
                    firma_valida = self.sphincs.verify(hash_actual, firma, user_pk)
                elif algoritmo == "dilithium":
                    firma_valida = ML_DSA_65.verify(user_pk, hash_actual, firma)
                else:
                    firma_valida = False
                    log_message("firmaApp.log",f"Algoritmo desconocido: {algoritmo}")
            else:
                firma_valida = False
            
            # Guardar el resultado
            resultados_validacion.append({
                "indice": i,
                "firma_valida": firma_valida,
                "cert_valido": cert_valido,
                "hash_verificacion": hash_actual,
                "firma_data": firma_data
            })
            
            # Calcular el siguiente hash para la cascada si hay más firmas para verificar
            if i > 0 and "hash_visual_signature" in firma_data:
                hash_visual = bytes.fromhex(firma_data["hash_visual_signature"])
                # Operación "resta" conceptual para obtener el hash anterior
                hash_actual = bytes(a ^ b for a, b in zip(hash_actual, hash_visual))
                log_message("firmaApp.log",f"Hash calculado para firma {i}: {hash_actual.hex()[:10]}...")
        
        # FASE 2: Mostrar los resultados en orden original (de la más antigua a la más reciente)
        resultados_validacion.reverse()
        
        for resultado in resultados_validacion:
            i = resultado["indice"]
            firma_data = resultado["firma_data"]
            firma_valida = resultado["firma_valida"]
            cert_valido = resultado["cert_valido"]
            
            # Extraer datos para la visualización
            nombre = firma_data["certificado_autenticacion"].get("nombre", "Desconocido")
            fecha_firma = firma_data.get("fecha_firma", "Desconocida")
            if isinstance(fecha_firma, str) and fecha_firma.startswith('20'):
                try:
                    fecha_obj = datetime.fromisoformat(fecha_firma)
                    fecha_firma = fecha_obj.strftime("%d/%m/%Y %H:%M:%S")
                except:
                    pass
            
            algoritmo = firma_data["certificado_autenticacion"].get("algoritmo", "sphincs").lower()
            
            # Actualizar contadores
            if firma_valida:
                valid_count += 1
            else:
                invalid_count += 1
            
            # Crear frame para esta firma
            firma_frame = tk.Frame(scrollable_frame, relief=tk.RIDGE, bd=1)
            firma_frame.pack(fill=tk.X, pady=5, padx=5)
            
            # Configurar colores según resultado
            bg_color = "#e8f5e9" if firma_valida else "#ffebee"  # Verde claro o rojo claro
            firma_frame.configure(bg=bg_color)
            
            # Información de la firma
            header_frame = tk.Frame(firma_frame, bg=bg_color)
            header_frame.pack(fill=tk.X, padx=5, pady=5)
            
            # Número de firma e icono de estado
            status_icon = "✓" if firma_valida else "✗"
            status_color = "#388e3c" if firma_valida else "#d32f2f"  # Verde oscuro o rojo oscuro
            
            tk.Label(
                header_frame, 
                text=f"{i+1}. ",
                font=("Arial", 11, "bold"),
                bg=bg_color
            ).pack(side=tk.LEFT)
            
            tk.Label(
                header_frame, 
                text=status_icon,
                font=("Arial", 14, "bold"),
                fg=status_color,
                bg=bg_color
            ).pack(side=tk.LEFT)
            
            tk.Label(
                header_frame, 
                text=f" {nombre}",
                font=("Arial", 11, "bold"),
                bg=bg_color
            ).pack(side=tk.LEFT)
            
            # Detalles de la firma
            details_frame = tk.Frame(firma_frame, bg=bg_color)
            details_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
            
            tk.Label(
                details_frame, 
                text=f"Fecha: {fecha_firma}",
                font=("Arial", 10),
                bg=bg_color
            ).pack(anchor="w")
            
            tk.Label(
                details_frame, 
                text=f"Algoritmo: {algoritmo.upper()}",
                font=("Arial", 10),
                bg=bg_color
            ).pack(anchor="w")
            
            tk.Label(
                details_frame, 
                text=f"Estado: {'Válida' if firma_valida else 'No válida'}",
                font=("Arial", 10, "bold"),
                fg=status_color,
                bg=bg_color
            ).pack(anchor="w")
            
            if not cert_valido:
                tk.Label(
                    details_frame, 
                    text="El certificado no es válido o ha expirado",
                    font=("Arial", 10, "italic"),
                    fg="#d32f2f",
                    bg=bg_color
                ).pack(anchor="w")
        
        # Resumen de verificación
        summary_frame = tk.Frame(results_window)
        summary_frame.pack(fill=tk.X, padx=10, pady=10)
        
        if invalid_count == 0 and valid_count > 0:
            bg_summary = "#e8f5e9"  # Verde claro
            fg_summary = "#388e3c"  # Verde oscuro
            summary_text = f"✓ Todas las firmas son válidas ({valid_count})"
        elif valid_count == 0:
            bg_summary = "#ffebee"  # Rojo claro
            fg_summary = "#d32f2f"  # Rojo oscuro
            summary_text = f"✗ Ninguna firma es válida ({invalid_count})"
        else:
            bg_summary = "#fff3e0"  # Naranja claro
            fg_summary = "#e65100"  # Naranja oscuro
            summary_text = f"⚠ Algunas firmas no son válidas ({valid_count} válidas, {invalid_count} no válidas)"
        
        summary_label = tk.Label(
            summary_frame, 
            text=summary_text,
            font=("Arial", 12, "bold"),
            fg=fg_summary,
            bg=bg_summary,
            padx=10,
            pady=5
        )
        summary_label.pack(fill=tk.X)
        
        # Botón para cerrar
        tk.Button(
            results_window, 
            text="Cerrar", 
            font=("Arial", 11),
            command=results_window.destroy,
            width=10
        ).pack(pady=10)

    def register_protocol_handler(self):
        try:
            if sys.platform != "win32":
                log_message("firmaApp.log","Registro de protocolo solo disponible en Windows")
                return False
                
            import winreg
            
            # Obtener ruta del ejecutable actual
            if getattr(sys, 'frozen', False):
                exe_path = sys.executable  # Si es ejecutable compilado
            else:
                exe_path = f'"{sys.executable}" "{os.path.abspath(__file__)}"'  # Python + script
                
            # Registrar protocolo autofirma://
            key_name = r"Software\Classes\autofirma"
            
            # Crear clave principal
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_name)
            winreg.SetValue(key, "", winreg.REG_SZ, "URL:AutoFirma Protocol")
            winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")
            
            # Crear comando (añadir comillas para asegurar que se interpreta correctamente)
            cmd_key = winreg.CreateKey(key, r"shell\open\command")
            
            # CAMBIO: Encerrar el argumento %1 entre comillas para evitar problemas con espacios
            winreg.SetValue(cmd_key, "", winreg.REG_SZ, f'{exe_path} --verify "%1"')
            
            winreg.CloseKey(cmd_key)
            winreg.CloseKey(key)
            
            log_message("firmaApp.log","Protocolo 'autofirma://' registrado correctamente")
            return True
        except Exception as e:
            log_message("firmaApp.log",f"Error al registrar protocolo: {e}")
            return False
        
    def verify_from_uri(self, uri):
        """Extrae la ruta del PDF desde una URI autofirma:// y verifica el documento"""
        try:
            log_message("firmaApp.log",f"Procesando URI: {uri}")
            
            if uri.startswith("autofirma://"):
                encoded_path = uri[len("autofirma://"):]
                encoded_path = encoded_path.rstrip('/')
                
                # Caso especial para el nuevo marcador "CURRENT_PDF"
                if encoded_path.upper() == "CURRENT_PDF":
                    # Detectar automáticamente el PDF activo
                    file_path = self.detect_active_pdf()
                    
                    if not file_path:
                        messagebox.showerror("Error", "No se pudo detectar automáticamente el PDF activo. Por favor, asegúrese de que el PDF esté abierto y visible en primer plano.")
                        return False
                    
                    log_message("firmaApp.log",f"PDF activo detectado: {file_path}")
                elif encoded_path.lower() == "test":
                    messagebox.showinfo("Prueba exitosa", "El protocolo autofirma:// funciona correctamente.")
                    log_message("firmaApp.log","Prueba del protocolo exitosa")
                    return True
                else:
                    # Manejar el caso de URIs antiguas (con ruta codificada)
                    try:
                        import base64
                        file_path = base64.urlsafe_b64decode(encoded_path.encode()).decode()
                    except Exception:
                        messagebox.showerror("Error", "No se pudo decodificar la ruta del PDF. Intente hacer clic en otra firma.")
                        return False
                
                # Verificar el PDF detectado
                if os.path.exists(file_path):
                    doc = fitz.open(file_path)
                    metadata = doc.metadata
                    doc.close()
                    
                    meta_data = json.loads(metadata.get("keywords", "{}"))
                    firmas = meta_data.get("firmas", [])
                    
                    if not firmas:
                        messagebox.showerror("Error", "No se encontraron firmas en el documento.")
                        return False
                    
                    # Calcular hash del documento
                    hash_documento_actual = self.calcular_hash_documento(file_path)
                    
                    # Mostrar resultados
                    self.mostrar_resultados_firmas(file_path, firmas, hash_documento_actual)
                    return True
                else:
                    messagebox.showerror("Error", f"No se encuentra el archivo: {file_path}")
                    return False
            else:
                messagebox.showerror("Error", "El formato de la URI no es válido.")
                return False
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar desde URI: {e}")
            log_message("firmaApp.log",f"Error al verificar desde URI: {e}")
            return False
        

    def detect_active_pdf(self):
        """Detecta automáticamente el PDF activo incluso cuando esta app está en primer plano"""
        try:
            log_message("firmaApp.log","Intentando detectar el PDF activo...")
            
            if sys.platform == "win32":
                try:
                    import win32gui
                    import win32process
                    import psutil
                    import os
                    import re
                    import glob
                    from datetime import datetime, timedelta
                    
                    # Estrategia 1: Buscar PDFs abiertos por cualquier proceso de visor PDF
                    log_message("firmaApp.log","Buscando PDFs abiertos en procesos activos...")
                    pdf_viewers = ["acrord32.exe", "acrobat.exe", "chrome.exe", "msedge.exe", 
                                "firefox.exe", "SumatraPDF.exe", "FoxitReader.exe"]
                    
                    pdf_files_found = []
                    
                    # Buscar en todos los procesos, no solo el activo
                    for proc in psutil.process_iter(['pid', 'name']):
                        if any(viewer.lower() in proc.info['name'].lower() for viewer in pdf_viewers):
                            try:
                                p = psutil.Process(proc.info['pid'])
                                for file in p.open_files():
                                    if file.path.lower().endswith('.pdf'):
                                        pdf_files_found.append((file.path, p.create_time()))
                                        log_message("firmaApp.log",f"PDF encontrado en proceso {p.name()}: {file.path}")
                            except (psutil.AccessDenied, psutil.NoSuchProcess):
                                continue
                    
                    # Si encontramos PDFs, devolver el más reciente
                    if pdf_files_found:
                        # Ordenar por tiempo de creación del proceso, más reciente primero
                        pdf_files_found.sort(key=lambda x: x[1], reverse=True)
                        log_message("firmaApp.log",f"PDF seleccionado (proceso más reciente): {pdf_files_found[0][0]}")
                        return pdf_files_found[0][0]
                    
                    # Estrategia 2: Buscar PDFs recientemente modificados
                    log_message("firmaApp.log","Buscando PDFs recientemente modificados...")
                    recent_files = []
                    locations = [
                        os.path.join(os.path.expanduser("~"), "Desktop"),
                        os.path.join(os.path.expanduser("~"), "Documents"),
                        os.path.join(os.path.expanduser("~"), "Downloads"),
                        "C:\\Temp",
                        os.environ.get('TEMP', '')
                    ]
                    
                    # Buscar PDFs modificados en los últimos 5 minutos
                    cutoff_time = datetime.now() - timedelta(minutes=5)
                    
                    for location in locations:
                        if os.path.exists(location):
                            for root, _, files in os.walk(location):
                                for file in files:
                                    if file.lower().endswith('.pdf'):
                                        file_path = os.path.join(root, file)
                                        try:
                                            mtime = os.path.getmtime(file_path)
                                            mtime_dt = datetime.fromtimestamp(mtime)
                                            if mtime_dt > cutoff_time:
                                                recent_files.append((file_path, mtime_dt))
                                        except:
                                            pass
                    
                    # Si encontramos archivos recientes, devolver el más reciente
                    if recent_files:
                        recent_files.sort(key=lambda x: x[1], reverse=True)
                        log_message("firmaApp.log",f"PDF seleccionado (modificado recientemente): {recent_files[0][0]}")
                        return recent_files[0][0]
                    
                    # Estrategia 3: Buscar en archivos temporales de navegadores
                    log_message("firmaApp.log","Buscando PDFs en archivos temporales...")
                    temp_files = []
                    
                    # Ubicaciones típicas de archivos temporales de navegadores
                    browser_temp_locations = [
                        os.path.join(os.environ.get('TEMP', ''), '*'),
                        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data', 'Default', 'Cache', '*'),
                        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Edge', 'User Data', 'Default', 'Cache', '*')
                    ]
                    
                    for pattern in browser_temp_locations:
                        for file_path in glob.glob(pattern):
                            if os.path.isfile(file_path):
                                try:
                                    with open(file_path, 'rb') as f:
                                        # Leer los primeros bytes para comprobar si es un PDF
                                        header = f.read(4)
                                        if header == b'%PDF':
                                            mtime = os.path.getmtime(file_path)
                                            temp_files.append((file_path, mtime))
                                except:
                                    pass
                    
                    if temp_files:
                        temp_files.sort(key=lambda x: x[1], reverse=True)
                        log_message("firmaApp.log",f"PDF temporal seleccionado: {temp_files[0][0]}")
                        return temp_files[0][0]
                    
                    # No se pudo encontrar ningún PDF activo
                    log_message("firmaApp.log","No se pudo detectar automáticamente el PDF activo")
                    return None
                    
                except ImportError as e:
                    log_message("firmaApp.log",f"Error: módulo necesario no instalado: {e}")
                    log_message("firmaApp.log","Para detección automática, instale los paquetes requeridos:")
                    log_message("firmaApp.log","pip install pywin32 psutil")
                    return None
            else:
                log_message("firmaApp.log","Detección automática solo disponible en Windows")
                return None
        except Exception as e:
            log_message("firmaApp.log",f"Error en detección automática: {e}")
            import traceback
            log_message("firmaApp.log",traceback.format_exc())
            return None
        
if __name__ == "__main__":
    # Comprobar si se inicia para verificación automática
    if len(sys.argv) > 1 and sys.argv[1] == "--verify":
        # Iniciar aplicación
        root = tk.Tk()
        app = AutoFirmaApp(root)
        
        # Verificar desde URI (autofirma://...)
        if len(sys.argv) > 2:
            uri = sys.argv[2]
            # Programar verificación para después de iniciar la UI
            root.after(500, lambda: app.verify_from_uri(uri))
        
        root.mainloop()
    else:
        # Inicialización normal
        root = tk.Tk()
        app = AutoFirmaApp(root)
        
        # Registrar el protocolo al iniciar la aplicación (solo una vez)
        app.register_protocol_handler()
        
        root.mainloop()
