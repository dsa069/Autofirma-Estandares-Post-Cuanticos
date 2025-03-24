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
        """Añade una firma escrita al PDF después de firmarlo digitalmente, permitiendo al usuario elegir 
        la posición directamente sobre el documento."""
        try:
            # Abrir el documento PDF
            doc = fitz.open(pdf_path)

            # 🔹 Obtener la fecha actual
            fecha_firma = datetime.now().strftime("%d/%m/%Y")

            # 🔹 Seleccionar página para la firma
            total_pages = len(doc)
            page_idx = 0  # Por defecto, primera página
            
            if total_pages > 1:
                # Crear un diálogo personalizado para seleccionar la página
                page_dialog = tk.Toplevel(self.root)
                page_dialog.title("Selección de página")
                page_dialog.geometry("500x400")  # Hacer el diálogo más grande para la vista previa
                page_dialog.resizable(False, False)
                page_dialog.transient(self.root)
                page_dialog.grab_set()
                
                tk.Label(page_dialog, text=f"Seleccione la página para la firma (1-{total_pages}):",
                        font=("Arial", 10)).pack(pady=10)
                
                # Frame para el spinbox y botones de navegación
                nav_frame = tk.Frame(page_dialog)
                nav_frame.pack(fill=tk.X, pady=5)
                
                # Variable para el número de página - AHORA EMPIEZA EN 1
                page_var = tk.StringVar(value="1")  # Por defecto PRIMERA página en lugar de la última
                
                # Función para actualizar la vista previa
                preview_label = tk.Label(page_dialog)
                preview_label.pack(pady=10, fill=tk.BOTH, expand=True)
                
                # Mantener referencia a la imagen
                preview_image = [None]
                
                def update_preview(page_num):
                    try:
                        # Convertir a índice base 0
                        page_idx = int(page_num) - 1
                        if 0 <= page_idx < total_pages:
                            # Renderizar la página seleccionada
                            page = doc[page_idx]
                            pix = page.get_pixmap(matrix=fitz.Matrix(0.3, 0.3))  # Escala reducida para la vista previa
                            img_data = pix.tobytes("ppm")
                            
                            # Convertir a imagen de PIL y luego a PhotoImage de tkinter
                            from PIL import Image, ImageTk
                            import io
                            
                            img = Image.open(io.BytesIO(img_data))
                            img_tk = ImageTk.PhotoImage(img)
                            
                            # Actualizar la etiqueta con la nueva imagen
                            preview_label.config(image=img_tk)
                            preview_image[0] = img_tk  # Mantener referencia para evitar que el garbage collector la elimine
                    except Exception as e:
                        print(f"Error al actualizar vista previa: {e}")
                
                def on_page_change(*args):
                    try:
                        page_num = int(page_var.get())
                        update_preview(page_num)
                    except ValueError:
                        pass
                
                # Botones de navegación
                def prev_page():
                    try:
                        current = int(page_var.get())
                        if current > 1:
                            page_var.set(str(current - 1))
                    except ValueError:
                        page_var.set("1")
                
                def next_page():
                    try:
                        current = int(page_var.get())
                        if current < total_pages:
                            page_var.set(str(current + 1))
                    except ValueError:
                        page_var.set(str(total_pages))
                
                # Centrar los controles de navegación
                # Crear un frame para contener los controles y centrarlo
                controls_frame = tk.Frame(nav_frame)
                controls_frame.pack(side=tk.TOP, fill=tk.X)
                
                # Espaciador a la izquierda para centrado
                tk.Label(controls_frame, width=10).pack(side=tk.LEFT, expand=True)
                
                # Añadir botones de navegación y campo de texto
                prev_btn = tk.Button(controls_frame, text="◀", command=prev_page)
                prev_btn.pack(side=tk.LEFT, padx=5)
                
                # Reemplazar spinbox con un Entry normal para eliminar las flechas arriba/abajo redundantes
                page_entry = tk.Entry(controls_frame, textvariable=page_var, width=5, justify=tk.CENTER)
                page_entry.pack(side=tk.LEFT, padx=5)
                
                next_btn = tk.Button(controls_frame, text="▶", command=next_page)
                next_btn.pack(side=tk.LEFT, padx=5)
                
                # Espaciador a la derecha para centrado
                tk.Label(controls_frame, width=10).pack(side=tk.LEFT, expand=True)
                
                # Validación del campo de texto al presionar Enter
                def validate_and_update(event):
                    try:
                        page_num = int(page_var.get())
                        if page_num < 1:
                            page_var.set("1")
                        elif page_num > total_pages:
                            page_var.set(str(total_pages))
                        update_preview(page_var.get())
                    except ValueError:
                        page_var.set("1")
                        update_preview("1")
                
                page_entry.bind("<Return>", validate_and_update)
                page_entry.bind("<FocusOut>", validate_and_update)
                
                # Actualizar cuando cambie el valor manualmente
                page_var.trace_add("write", on_page_change)
                
                # Mostrar la vista previa inicial (ahora es la primera página)
                update_preview("1")
                
                result = [None]  # Usamos una lista para almacenar el resultado
                
                def on_ok():
                    try:
                        page_num = int(page_var.get())
                        if 1 <= page_num <= total_pages:
                            result[0] = page_num - 1  # Ajustar a índice base 0
                            page_dialog.destroy()
                        else:
                            messagebox.showerror("Error", f"Ingrese un número entre 1 y {total_pages}")
                    except ValueError:
                        messagebox.showerror("Error", "Ingrese un número válido")
                        
                def on_cancel():
                    result[0] = -1  # Cancelar
                    page_dialog.destroy()
                    
                button_frame = tk.Frame(page_dialog)
                button_frame.pack(pady=10, fill=tk.X)
                tk.Button(button_frame, text="Aceptar", command=on_ok).pack(side=tk.LEFT, padx=10, expand=True)
                tk.Button(button_frame, text="Cancelar", command=on_cancel).pack(side=tk.RIGHT, padx=10, expand=True)
                
                self.root.wait_window(page_dialog)
                
                if result[0] == -1:
                    return False  # Usuario canceló
                    
                page_idx = result[0]
            
            # El resto de la función se mantiene igual...
            page = doc[page_idx]
        
        # Continuar con el código existente para posicionar la firma...
            
            # 🔹 Crear ventana para previsualizar el PDF y permitir al usuario hacer clic en la posición deseada
            preview_window = tk.Toplevel(self.root)
            preview_window.title(f"Seleccione dónde colocar la firma (Página {page_idx + 1} de {total_pages})")
            preview_window.geometry("800x800")
            preview_window.transient(self.root)
            
            # Añadir instrucciones en la parte superior
            tk.Label(preview_window, text="Haga clic en el lugar donde desea centrar la firma:", 
                    font=("Arial", 12)).pack(pady=5)
            
            # Frame para el canvas y la barra de desplazamiento
            frame = tk.Frame(preview_window)
            frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Crear barra de desplazamiento vertical
            v_scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL)
            v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            # Crear barra de desplazamiento horizontal
            h_scrollbar = tk.Scrollbar(frame, orient=tk.HORIZONTAL)
            h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
            
            # Crear canvas con barras de desplazamiento
            canvas = tk.Canvas(frame, yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            v_scrollbar.config(command=canvas.yview)
            h_scrollbar.config(command=canvas.xview)
            
            # Renderizar página del PDF a imagen
            pix = page.get_pixmap(matrix=fitz.Matrix(1.5, 1.5))  # Escala 1.5 para mejor calidad
            img_data = pix.tobytes("ppm")
            
            # Convertir a imagen de PIL y luego a PhotoImage de tkinter
            from PIL import Image, ImageTk
            import io
            
            img = Image.open(io.BytesIO(img_data))
            img_tk = ImageTk.PhotoImage(img)
            
            # Mostrar la imagen en el canvas
            canvas.create_image(0, 0, anchor=tk.NW, image=img_tk)
            canvas.config(scrollregion=canvas.bbox(tk.ALL))
            
            # Variable para almacenar las coordenadas seleccionadas
            selected_position = [None, None]
            signature_rect = [None]  # Para almacenar el rectángulo de previsualización
            
            # Definir tamaño de la firma - REDUCIDO A LA MITAD
            signature_height = 30   # Antes era 60
            signature_width = 175   # Antes era 350
            
            # Función para manejar clic en el canvas
            def on_canvas_click(event):
                # Obtener coordenadas del canvas
                x = canvas.canvasx(event.x)
                y = canvas.canvasy(event.y)
                
                # Guardar coordenadas del centro ajustadas a la escala del PDF
                selected_position[0] = x / 1.5  # Ajustar escala
                selected_position[1] = y / 1.5  # Ajustar escala
                
                # Calcular esquina superior izquierda para el rectángulo de previsualización
                x_top_left = x - (signature_width * 1.5) / 2
                y_top_left = y - (signature_height * 1.5) / 2
                
                # Eliminar rectángulo anterior si existe
                if signature_rect[0]:
                    canvas.delete(signature_rect[0])
                
                # Dibujar rectángulo de previsualización CENTRADO en el punto donde se hizo clic
                signature_rect[0] = canvas.create_rectangle(
                    x_top_left, y_top_left, 
                    x_top_left + signature_width * 1.5, y_top_left + signature_height * 1.5,
                    outline="blue", width=2
                )
                
                # Mostrar coordenadas seleccionadas
                status_var.set(f"Posición seleccionada: ({int(selected_position[0])}, {int(selected_position[1])})")
            
            canvas.bind("<Button-1>", on_canvas_click)
            
            # Etiqueta de estado
            status_var = tk.StringVar(value="Haga clic para seleccionar una posición")
            status_label = tk.Label(preview_window, textvariable=status_var)
            status_label.pack(pady=5)
            
            # Frame para botones
            btn_frame = tk.Frame(preview_window)
            btn_frame.pack(pady=10)
            
            # Variable para controlar si se completó la selección
            selection_completed = [False]
            
            def on_accept():
                if selected_position[0] is None or selected_position[1] is None:
                    messagebox.showwarning("Aviso", "Por favor, haga clic en el documento para seleccionar una posición.")
                    return
                    
                selection_completed[0] = True
                preview_window.destroy()
                
            def on_cancel():
                selected_position[0] = None
                selected_position[1] = None
                preview_window.destroy()
            
            tk.Button(btn_frame, text="Aceptar", command=on_accept).pack(side=tk.LEFT, padx=20)
            tk.Button(btn_frame, text="Cancelar", command=on_cancel).pack(side=tk.RIGHT, padx=20)
            
            # Necesario para mantener la referencia a la imagen
            preview_window.img_tk = img_tk
            
            # Esperar a que se cierre la ventana
            self.root.wait_window(preview_window)
            
            # Si el usuario canceló o no seleccionó posición
            if selected_position[0] is None or not selection_completed[0]:
                return False
            
            # 🔹 Calcular las coordenadas de la esquina superior izquierda a partir del centro
            x_center = selected_position[0]
            y_center = selected_position[1]
            x0 = x_center - (signature_width / 2)
            y0 = y_center - (signature_height / 2)
            rect = fitz.Rect(x0, y0, x0 + signature_width, y0 + signature_height)
            
            # 🔹 Agregar un rectángulo blanco como fondo
            page.draw_rect(rect, color=(0, 0, 0), fill=(1, 1, 1), overlay=True)
            
            # 🔹 Agregar un borde visible al rectángulo
            page.draw_rect(rect, color=(0, 0, 0), width=1.0, overlay=True)

            # 🔹 Agregar la firma escrita
            page.insert_textbox(
                rect, 
                f"Firmado por: {nombre_certificado}\nFecha: {fecha_firma}",
                fontsize=8,  # Tamaño de fuente reducido para la firma más pequeña
                fontname="helv",
                color=(0, 0, 0),
                align=1,  # Centrado
                overlay=True
            )

            # 🔹 Guardar el documento con la firma escrita
            doc.save(pdf_path, incremental=True, encryption=0)
            doc.close()

            messagebox.showinfo("Firma Escrita", "Firma escrita añadida correctamente.")
            self.log_message("Firma escrita añadida correctamente.")
            return True

        except Exception as e:
            messagebox.showerror("Error", f"Error al añadir firma escrita: {e}")
            self.log_message(f"Error al añadir firma escrita: {e}")
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
