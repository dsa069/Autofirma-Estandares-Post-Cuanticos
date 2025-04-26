import sys
import os
from backend.funcComunes import log_message, init_paths

BASE_DIR = init_paths()

import tkinter as tk
from tkinter import PhotoImage, messagebox, filedialog, simpledialog
from tkinterdnd2 import TkinterDnD # type: ignore
import customtkinter as ctk # type: ignore
from backend.funcFirma import register_protocol_handler
from frontend.compComunes import center_window, crear_vista_nueva, create_button, create_text, set_app_instance, setup_app_icons
from frontend.compFirma import create_drop_area, set_app_instance_autofirma

class AutoFirmaApp:
    def __init__(self, root):
        self.root = root 
        self.root.title("AutoFirma - Sphincs")
        self.root.geometry("700x584")
        self.root.resizable(False, False)
        self.root.configure(bg="#F5F5F5")
        center_window(self.root)
        setup_app_icons(self.root, BASE_DIR, "Diego")

        self.vista_inicial_autofirma()

    def vista_inicial_autofirma(self):
        vista = crear_vista_nueva(self.root)

        bienvenida_label = create_text(
            vista, text="Bienvenido a la aplicación de AutoFirma Post-Cuántica"
        )
        bienvenida_label.pack(pady=(30,10), padx=(50, 0))

        introduction_label = create_text(
            vista, text="Esta herramienta te permite generar certificados digitales y claves con criptografía resistentes a ataques cuánticos, garantizando la seguridad a largo plazo. " \
            "La aplicación utiliza estándares avanzados como Dilithium y SPHINCS+. "
            "Para crear firmar o validar un documento, selecciona el archivo PDF en el area inferior." 
        )
        introduction_label.pack(pady=(10,30), padx=(50, 0))
        
        def handle_selected_file(document_path):
            log_message("firmaApp.log", f"Archivo seleccionado: {document_path}")
            self.document_path = document_path 

        create_drop_area(vista, callback=handle_selected_file)

        botones_frame = ctk.CTkFrame(vista, fg_color="transparent")
        botones_frame.pack(padx=20, pady=10, expand=True)

        volver_btn = create_button(botones_frame, "Firmar", lambda: self)
        volver_btn.pack(side="left", padx=(0, 250))

        guardar_btn = create_button(botones_frame, "Verificar", lambda: self.verify_signatures(self.document_path))
        guardar_btn.pack(side="left")

    def load_certificate(self, tipo):
        """Carga el certificado del usuario según el tipo ('firmar' o 'autenticacion')."""
        try:
            from backend.funcFirma import cargar_datos_certificado, decrypt_private_key, enviar_alerta_certificado
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

            cert_data, user_pk, ent_pk, exp_date, issue_date = cargar_datos_certificado(cert_path, BASE_DIR)

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

                    user_sk = decrypt_private_key(encrypted_sk, password)

                    if user_sk:
                        break  # Clave descifrada correctamente
                    else:
                        messagebox.showerror("Error", "Contraseña incorrecta. Inténtalo de nuevo.")
                        intento += 1
                        if intento == 3:  # Mostrar alerta cada 3 intentos
                            enviar_alerta_certificado(cert_data["nombre"], cert_data["dni"])

            log_message("firmaApp.log",f"Certificado {tipo} cargado correctamente.")
            return user_sk, user_pk, ent_pk, issue_date, exp_date, cert_data
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar certificado {tipo}: {e}")
            log_message("firmaApp.log",f"Error al cargar certificado {tipo}: {e}")
            return None, None, None, None, None, None
        
    def add_written_signature(self, pdf_path, nombre_certificado):
        """Ventana unificada para seleccionar página y posición de firma."""
        import fitz  # type: ignore # PyMuPDF para manejar metadatos en PDFs
        from backend.funcFirma import añadir_firma_visual_pdf
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
                from PIL import Image, ImageTk # type: ignore
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

            return añadir_firma_visual_pdf(
            pdf_path, 
            result["page"], 
            result["position"],
            signature_width, 
            signature_height, 
            nombre_certificado
            )
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al seleccionar posición: {e}")
            log_message("firmaApp.log",f"Error al seleccionar posición: {e}")
            return False

    def sign_message(self):
        """Firma un documento digitalmente y permite añadir una firma escrita opcional en el PDF."""
        try:
            from backend.funcFirma import cargar_certificado_autenticacion, copiar_contenido_pdf, firmar_documento_pdf
            # Cargar certificado de firma
            user_sk, _, _, _, _, cert_firma = self.load_certificate("firmar")
            if not user_sk:
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

            success, cert_auth, error_msg = cargar_certificado_autenticacion(cert_firma, BASE_DIR)
            if not success:
                messagebox.showerror("Error", error_msg)
                return

            # GUARDAR EL DOCUMENTO FIRMADO DIGITALMENTE
            if not copiar_contenido_pdf(file_path, save_path):
                messagebox.showerror("Error", "No se pudo copiar el contenido del archivo original.")
                return

            visual_signature_hash = None
            
            # PREGUNTAR AL USUARIO SI DESEA AÑADIR FIRMA ESCRITA
            agregar_firma = messagebox.askyesno("Firma Escrita", "¿Desea añadir una firma escrita en el PDF?")
            if agregar_firma:
                success, visual_hash = self.add_written_signature(save_path, cert_firma["nombre"])
                if success:
                    visual_signature_hash = visual_hash
                else:
                    # Si se cancela la firma escrita, seguimos con la firma digital normal
                    log_message("firmaApp.log","Firma escrita cancelada, continuando con firma digital.")

            # CALCULAR HASH DEL DOCUMENTO (después de añadir la firma escrita si se solicitó)
            resultado, mensaje = firmar_documento_pdf(save_path, user_sk, cert_firma, cert_auth, visual_signature_hash)
            if resultado:
                messagebox.showinfo("Éxito", mensaje)
            else:
                messagebox.showerror("Error", mensaje)

        except Exception as e:
            messagebox.showerror("Error", f"Error al firmar documento: {e}")
            log_message("firmaApp.log",f"Error al firmar documento: {e}")

    def verify_signatures(self, file_path):
        """Muestra los resultados de la verificación de múltiples firmas en cascada."""
        from backend.funcFirma import determinar_estilo_firmas_validiadas, verificar_firmas_cascada
        from backend.funcComunes import format_iso_display
        
        try:
            from backend.funcFirma import extraer_firmas_documento
            # Llamar a la función del backend
            success, firmas, hash_documento_actual = extraer_firmas_documento(file_path)
            
            # Manejar resultados
            if not success:
                messagebox.showerror("Error", "No se encontraron firmas válidas en el documento.")
                return
                    
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar firmas: {e}")
            log_message("firmaApp.log",f"Error al verificar firmas: {e}")

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
        
        resultados_validacion = verificar_firmas_cascada(firmas, hash_documento_actual, BASE_DIR)
        
        # FASE 2: Mostrar los resultados en orden original (de la más antigua a la más reciente)
        
        for resultado in resultados_validacion:
            i = resultado["indice"]
            firma_data = resultado["firma_data"]
            firma_valida = resultado["firma_valida"]
            cert_valido = resultado["cert_valido"]
            integridad_valida = resultado["integridad_valida"]

            todo_valido = firma_valida and cert_valido and integridad_valida
            
            # Extraer datos para la visualización
            nombre = firma_data["certificado_autenticacion"].get("nombre", "Desconocido")
            fecha_firma = format_iso_display(firma_data.get("fecha_firma", "Desconocida"))
            
            algoritmo = firma_data["certificado_autenticacion"].get("algoritmo", "sphincs").lower()
            
            # Actualizar contadores
            if todo_valido:
                valid_count += 1
            else:
                invalid_count += 1
            
            # Crear frame para esta firma
            firma_frame = tk.Frame(scrollable_frame, relief=tk.RIDGE, bd=1)
            firma_frame.pack(fill=tk.X, pady=5, padx=5)
            
            # Configurar colores según resultado
            bg_color = "#e8f5e9" if todo_valido else "#ffebee"  # Verde claro o rojo claro
            firma_frame.configure(bg=bg_color)
            
            # Información de la firma
            header_frame = tk.Frame(firma_frame, bg=bg_color)
            header_frame.pack(fill=tk.X, padx=5, pady=5)
            
            # Número de firma e icono de estado
            status_icon = "✓" if todo_valido else "✗"
            status_color = "#388e3c" if todo_valido else "#d32f2f"  # Verde oscuro o rojo oscuro
            
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
        
        bg_summary, fg_summary, summary_text = determinar_estilo_firmas_validiadas(valid_count, invalid_count)

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
        
    def verify_from_uri(self, uri):
        """Maneja la UI y llama al backend"""
        from backend.funcFirma import process_uri
        # process_uri devuelve: (success, file_path, firmas, hash_documento)
        success, file_path = process_uri(uri)
        
        if not success:
            messagebox.showerror("Error", "No se pudo verificar el documento. Por favor asegúrese de que el PDF esté abierto y sea accesible.")
            return False
            
        # Mostrar resultados en la UI usando los valores desempaquetados de la tupla
        self.verify_signatures(file_path)
        return True
        
if __name__ == "__main__":
    # Comprobar si se inicia para verificación automática
    if len(sys.argv) > 1 and sys.argv[1] == "--verify":
        # Iniciar aplicación
        root = TkinterDnD.Tk()
        app = AutoFirmaApp(root)
        #set_app_instance(app)
        #set_app_instance_autofirma(app)
        
        # Verificar desde URI (autofirma://...)
        if len(sys.argv) > 2:
            uri = sys.argv[2]
            # Programar verificación para después de iniciar la UI
            root.after(500, lambda: app.verify_from_uri(uri))
        
        root.mainloop()
    else:
        # Inicialización normal
        root = TkinterDnD.Tk()
        app = AutoFirmaApp(root)
        set_app_instance(app)
        set_app_instance_autofirma(app)
        
        # Registrar el protocolo al iniciar la aplicación (solo una vez)
        register_protocol_handler()
        
        root.mainloop()
