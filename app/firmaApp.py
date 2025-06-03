import sys
import os
import tkinter as tk
from tkinter import messagebox
from tkinterdnd2 import TkinterDnD # type: ignore
import customtkinter as ctk # type: ignore
from backend.funcComunes import log_message, init_paths
from backend.funcFirma import register_protocol_handler, set_base_dir_back_firma
from frontend.compComunes import center_window, crear_vista_nueva, create_button, set_app_instance, set_base_dir, setup_app_icons, resize_image_proportionally
from frontend.compFirma import set_app_instance_autofirma

BASE_DIR = init_paths()

class AutoFirmaApp:
    def __init__(self, root):
        self.root = root 
        self.root.title("Autofirma SafeInQ")
        self.root.geometry("700x584")
        self.root.resizable(False, False)
        self.root.configure(bg="#F5F5F5")
        center_window(self.root)
        setup_app_icons(self.root, "Diego")

        self.vista_inicial_autofirma()

    def vista_inicial_autofirma(self):
        from frontend.compComunes import create_text
        from frontend.compFirma import create_pdf_area

        self.document_path = None
        vista = crear_vista_nueva(self.root)

        bienvenida_label = create_text(
                vista, text="Bienvenido a Autofirma SafeInQ"
        )
        bienvenida_label.pack(pady=(30,10), padx=(50, 0))

        introduction_label = create_text(
            vista, text="Esta herramienta te permite firmar digitalmente documentos con criptografía resistente a ataques cuánticos, garantizando la seguridad a largo plazo. " \
            "Puedes seleccionar un documento, en el area inferior, para firmarlo con tu certificado digital, o bien, validar una firma existente para comprobar su autenticidad. La aplicación utiliza estándares avanzados como Dilithium y SPHINCS+."
            )
        introduction_label.pack(pady=(10,30), padx=(50, 0))
        
        def handle_selected_file(document_path):
            log_message("firmaApp.log", f"Archivo seleccionado: {document_path}")
            self.document_path = document_path

        create_pdf_area(vista, callback=handle_selected_file)

        botones_frame = ctk.CTkFrame(vista, fg_color="transparent")
        botones_frame.pack(padx=20, pady=10, expand=True)

        firmar_btn = create_button(botones_frame, "Firmar", lambda: self.sign_document() if self.document_path else messagebox.showinfo("Aviso", "Primero seleccione un documento para firmar"))
        firmar_btn.pack(side="left", padx=(0, 250))

        verificar_btn = create_button(botones_frame, "Verificar", lambda: self.verify_signatures() if self.document_path else messagebox.showinfo("Aviso", "Primero seleccione un documento para verificar"))
        verificar_btn.pack(side="left")

    def verify_signatures(self):
        """Muestra los resultados de la verificación de múltiples firmas en cascada."""
        from backend.funcFirma import determinar_estilo_firmas_validadas, verificar_firmas_cascada, extraer_firmas_documento
        from frontend.compFirma import create_certificate_list

        # Llamar a la función del backend
        success, firmas, hash_documento_actual = extraer_firmas_documento(self.document_path)
        
        if not success:
            messagebox.showerror("Error", "No se encontraron firmas válidas en el documento.")
            return
                    
        resultados_validacion = verificar_firmas_cascada(firmas, hash_documento_actual)

        vista = crear_vista_nueva(self.root)

        certificados_frame, valid_count, invalid_count = create_certificate_list(vista, resultados_validacion)
        
        summary_img, summary_text = determinar_estilo_firmas_validadas(valid_count, invalid_count)
        
        # Crear un frame para el resultado
        resultado_frame = ctk.CTkFrame(vista, fg_color="#f5f5f5")  
        resultado_frame.pack(padx=20, pady=15, fill="x")

        img = resize_image_proportionally(summary_img, 100)
        label_imagen = ctk.CTkLabel(resultado_frame, image=img, text="", bg_color="#f5f5f5")
        label_imagen.grid(row=0, column=0, padx=(10, 10), sticky="w")

        label_texto = ctk.CTkLabel(
            resultado_frame,
            text=summary_text,
            font=("Inter", 25),
            text_color="#000000",
            bg_color="#f5f5f5"
        )
        label_texto.grid(row=0, column=1, padx=(0, 10), sticky="w", pady=(5, 0))
        
        # Frame para el pdf
        doc_label = ctk.CTkLabel(vista, text="Documento validado:",
                                font=("Inter", 19), text_color="#111111")
        doc_label.pack(anchor="w", padx=(30,0), pady=(5,0))

        fondo_pdf_frame = ctk.CTkFrame(
            vista,
            width=620,
            height=75,
            fg_color="white",
            corner_radius=25,
            border_width=1,
            border_color="#E0E0E0"
        )
        fondo_pdf_frame.pack(pady=5)
        fondo_pdf_frame.pack_propagate(False)

        img_pdf = resize_image_proportionally("adobe", 50)
        image_label = ctk.CTkLabel(fondo_pdf_frame, image=img_pdf, bg_color="transparent", text="")
        image_label.image = img_pdf
        image_label.pack(side="left", padx=20)

        pdf_frame = ctk.CTkFrame(fondo_pdf_frame, fg_color="transparent")
        pdf_frame.pack(side="left", expand=True, anchor="w")

        filename = os.path.basename(self.document_path)
        folder_path = os.path.dirname(self.document_path)

        label_title = ctk.CTkLabel(
            pdf_frame,
            text=filename,
            text_color="#111111",
            font=("Inter", 18),
            fg_color="transparent",
            anchor="w"
        )
        label_title.pack(anchor="w")

        label_path = ctk.CTkLabel(
            pdf_frame,
            text=folder_path,
            text_color="#555555",
            font=("Inter", 14),
            fg_color="transparent",
            anchor="w"
        )
        label_path.pack(anchor="w")

        # Frame para los certificados
        certificados_label = ctk.CTkLabel(vista, text="Firmas detectadas:",
                                font=("Inter", 19), text_color="#111111")
        certificados_label.pack(anchor="w", padx=(30,0), pady=(10,0))
        certificados_frame.pack(pady=5)

        volver_btn = create_button(vista, "Finalizar", lambda: self.vista_inicial_autofirma())
        volver_btn.pack(pady=20)

    def sign_document(self):
        """Firma un documento digitalmente y permite añadir una firma escrita opcional en el PDF."""
        from frontend.compComunes import create_text_field_with_title
        from frontend.compFirma import create_cert_area, create_checkbox

        password_trys = [0]  # Using a mutable object (list) to maintain state

        cert_file_path = [None]
        def handle_selected_cert(cert_path):
            log_message("firmaApp.log", f"Archivo seleccionado: {cert_path}")
            cert_file_path[0] = cert_path

        vista = crear_vista_nueva(self.root)

        titulo_label = ctk.CTkLabel(vista, text="Firmar un documento", font=("Inter", 25), fg_color="transparent")
        titulo_label.pack(pady=30)

        cert_area_container = ctk.CTkFrame(vista, fg_color="transparent")
        cert_area_container.pack(pady=(10, 10), anchor="w", fill="x")

        label = ctk.CTkLabel(cert_area_container, text="Selecciona el certificado de firma:", font=("Inter", 17), text_color="#111111")
        label.pack(anchor="w", padx= 30)

        cert_area = create_cert_area(cert_area_container, callback= handle_selected_cert)
        cert_area.pack(anchor="center")

        pass_container = ctk.CTkFrame(vista, fg_color="transparent")
        pass_container.pack(padx= 30, anchor="w", fill="x", pady=30)

        pass_field = create_text_field_with_title(pass_container, "Contraseña del certificado:", "Escriba la contraseña de nuevo")
        pass_field.configure(show="*")

        visible_sign_check = create_checkbox(vista, "Firma visible en dentro del pdf")

        botones_frame = ctk.CTkFrame(vista, fg_color="transparent")
        botones_frame.pack(padx=20, pady=10, expand=True)

        volver_btn = create_button(botones_frame, "Cancelar", lambda: self.vista_inicial_autofirma())
        volver_btn.pack(side="left", padx=(0, 250))

        guardar_btn = create_button(botones_frame, "Firmar", lambda: verify_and_create_sign())
        guardar_btn.pack(side="left")

        def verify_and_create_sign():
            try:
                from backend.funcFirma import enviar_alerta_certificado, cargar_certificado_autenticacion, copiar_contenido_pdf, firmar_documento_pdf, cargar_datos_certificado, decrypt_private_key

                firma_cert_path = cert_file_path[0]
                password = pass_field.get()
                visible_sign = visible_sign_check.get()

                #----------------------OBTENEMOS DATOS CERTIFICADO DE FIRMA----------------------
                if not firma_cert_path:
                    messagebox.showerror("Error", "No se ha seleccionado un certificado de firma.")
                    return

                cert_firma, _, _, _, _ = cargar_datos_certificado(firma_cert_path)

                #-----------------------VERIFICAMOS LA CONTRASEÑA DEL CERTIFICADO----------------------
                encrypted_sk = cert_firma.get("user_secret_key")
                if not encrypted_sk:
                    log_message("firmaApp.log","No se encontró la clave privada cifrada en el certificado.")
                    raise ValueError("No se encontró la clave privada cifrada en el certificado.")

                user_sk = decrypt_private_key(encrypted_sk, password)

                if not user_sk:
                    password_trys[0] += 1
                    messagebox.showerror("Error", "Contraseña incorrecta. Inténtalo de nuevo.")
                    log_message("firmaApp.log",f"Contraseña incorrecta para el certificado de firma. Intento {password_trys[0]}")
                    if password_trys[0] == 3:
                        enviar_alerta_certificado(cert_firma["nombre"], cert_firma["dni"])
                    return
                
                #---------------BUSCAMOS EL CERTIFICADO DE AUTENTICACION ASOCIADO----------------------
                success, cert_auth, error_msg = cargar_certificado_autenticacion(cert_firma)
                if not success:
                    log_message("firmaApp.log", error_msg)
                    raise ValueError(error_msg)
                
                # -----------------GUARDAR EL DOCUMENTO FIRMADO---------------------
                original_filename = os.path.basename(self.document_path)
                filename_without_ext, extension = os.path.splitext(original_filename)
                
                from tkinter import filedialog
                save_path = filedialog.asksaveasfilename(
                    title="Guardar nuevo documento firmado",
                    initialfile=f"{filename_without_ext}_firmado{extension}",
                    initialdir= os.path.join(os.path.expanduser("~"), "Desktop"),
                    defaultextension=".pdf",
                    filetypes=[("Archivos PDF", "*.pdf")],
                )

                if not save_path:
                    messagebox.showinfo("Cancelado", "Firma cancelada, no se ha guardado el archivo.")
                    return

                # GUARDAR EL DOCUMENTO FIRMADO DIGITALMENTE
                if not copiar_contenido_pdf(self.document_path, save_path):
                    log_message("firmaApp.log", "No se pudo copiar el contenido del archivo original.")
                    raise ValueError("No se pudo copiar el contenido del archivo original.")

                # -------------------PREGUNTAR AL USUARIO SI DESEA AÑADIR FIRMA ESCRITA---------------------
                visual_signature_hash = None
                
                if visible_sign:
                    success, visual_hash = self.add_written_signature(save_path, cert_firma["nombre"])
                    if success:
                        visual_signature_hash = visual_hash
                    else:
                        # Si se cancela la firma escrita, seguimos con la firma digital normal
                        log_message("firmaApp.log","Firma escrita cancelada, continuando con firma digital.")

                #-------------------FIRMAR EL DOCUMENTO---------------------
                resultado, _ = firmar_documento_pdf(save_path, user_sk, cert_firma, cert_auth, visual_signature_hash)

                if resultado:
                    self.document_path = save_path

                self.root.geometry("700x584")
                center_window(self.root)

                self.vista_resultado_firma(resultado, cert_firma)

            except Exception as e:
                log_message("firmaApp.log",f"Error al firmar documento: {e}")
                self.root.geometry("700x584")
                center_window(self.root)
                self.vista_resultado_firma(False, cert_firma)

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

            self.root.geometry("700x750")
            center_window(self.root)

            vista = crear_vista_nueva(self.root)

            titulo_label = ctk.CTkLabel(vista, text="Ubicar firma visible", font=("Inter", 25), fg_color="transparent")
            titulo_label.pack(pady=20)

            label = ctk.CTkLabel(vista, text="Seleccione una página y haga clic en ella en la posición donde desea ubicar la firma:", font=("Inter", 17), text_color="#111111")
            label.pack(anchor="w", padx= 30)
            
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
                
                # Renderizar página con escala de 0.6
                pix = doc[page_num].get_pixmap(matrix=fitz.Matrix(0.6, 0.6))
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
                    canvas_width = 400  # Ancho aproximado del canvas
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
                real_x = x_adjusted / 0.6  # Ajustar por la escala
                real_y = y_adjusted / 0.6  # Ajustar por la escala
                
                # Actualizar variables - estas son las coordenadas exactas de la esquina superior izquierda
                selected_x.set(int(real_x - signature_width/2))
                selected_y.set(int(real_y - signature_height/2))
                
                # Eliminar rectángulo anterior si existe
                if signature_rect[0]:
                    canvas.delete(signature_rect[0])
                
                # Dibujar rectángulo en la posición seleccionada
                rect_x = x_adjusted - (signature_width * 0.6) / 2
                rect_y = y_adjusted - (signature_height * 0.6) / 2
                
                signature_rect[0] = canvas.create_rectangle(
                    rect_x + offset_x[0], rect_y + offset_y[0], 
                    rect_x + (signature_width * 0.6) + offset_x[0], 
                    rect_y + (signature_height * 0.6) + offset_y[0],
                    outline="black", width=2
                )
                    
            def on_accept():
                if selected_x.get() == 0 and selected_y.get() == 0:
                    messagebox.showwarning("Aviso", "Por favor, seleccione una posición haciendo clic en la página.")
                    return
                
                result["success"] = True
                result["page"] = int(current_page.get()) - 1
                result["position"] = (selected_x.get(), selected_y.get())
                vista.destroy()
                #return True, None
            
            def on_cancel():
                result["success"] = False
                vista.destroy()
                """return False, None"""
            
            # Panel principal con altura fija para mostrar la página y seleccionar posición
            preview_frame = tk.Frame(vista, height=500, bg="#F5F5F5", borderwidth=0, highlightthickness=0)
            preview_frame.pack(fill=tk.X, padx=0, pady=0)
            preview_frame.pack_propagate(False)  # Evitar que el frame cambie de tamaño
            
            # Canvas con tamaño fijo para mostrar la página
            canvas = tk.Canvas(preview_frame, bg="#F5F5F5", width=400, height=500, borderwidth=0, highlightthickness=0)
            canvas.pack(expand=True)
            
            # Vincular evento de clic
            canvas.bind("<Button-1>", on_canvas_click)
            
            # CAMBIO: Ahora crear el selector de página DESPUÉS de la previsualización
            page_frame_container = tk.Frame(vista, bg="#F5F5F5")
            page_frame_container.pack(fill=tk.X, pady=10)
            
            page_frame = tk.Frame(page_frame_container, bg="#F5F5F5")
            page_frame.pack(side=tk.TOP, pady=5)
            
            # Etiqueta y selector de página
            tk.Label(page_frame, text="Página:", font=("Arial", 11), bg="#F5F5F5").pack(side=tk.LEFT, padx=5)
            
            # Botón página anterior
            prev_btn = tk.Button(page_frame, text="◀", command=lambda: change_page(-1), bg="#DCDCDC")
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
            next_btn = tk.Button(page_frame, text="▶", command=lambda: change_page(1), bg="#DCDCDC")
            next_btn.pack(side=tk.LEFT, padx=5)
            
            # Etiqueta de total de páginas
            tk.Label(page_frame, text=f"de {total_pages}", font=("Arial", 11), bg="#F5F5F5").pack(side=tk.LEFT, padx=5)
                
            # Botones de aceptar/cancelar
            botones_frame = ctk.CTkFrame(vista, fg_color="transparent")
            botones_frame.pack(padx=20, pady=10, expand=True)

            volver_btn = create_button(botones_frame, "Cancelar", lambda: on_cancel())
            volver_btn.pack(side="left", padx=(0, 250))

            guardar_btn = create_button(botones_frame, "Firmar", lambda: on_accept())
            guardar_btn.pack(side="left")

            # Mostrar vista previa inicial después de crear el canvas
            vista.update()
            update_preview()
            
            # Esperar a que se cierre la ventana
            self.root.wait_window(vista)
            
            # Resto del código igual que antes para añadir la firma al PDF
            if not result["success"]:
                return False, None

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
            return False, None

    def vista_resultado_firma(self, success, cert):
        from frontend.compFirma import create_certificate_row

        vista = crear_vista_nueva(self.root)

        # Crear un frame para el resultado
        resultado_frame = ctk.CTkFrame(vista, fg_color="#f5f5f5")  
        resultado_frame.pack(padx=20, pady=(30,40))

        img = resize_image_proportionally("tick" if success else "error", 100)
        label_imagen = ctk.CTkLabel(resultado_frame, image=img, text="", bg_color="#f5f5f5")
        label_imagen.grid(row=0, column=0, padx=(0, 30))

        label_texto = ctk.CTkLabel(
            resultado_frame,
            text="El documento se firmó correctamente" if success else "La operación de firma ha fallado",
            font=("Inter", 25),
            text_color="#000000",
            bg_color="#f5f5f5"
        )
        label_texto.grid(row=0, column=1, pady=(5, 0))

        # Frame para el pdf
        if self.document_path:
            doc_label = ctk.CTkLabel(vista, text="Documento firmado:",
                                    font=("Inter", 19), text_color="#111111")
            doc_label.pack(anchor="w", padx=(30,0), pady=(0,15))

            fondo_pdf_frame = ctk.CTkFrame(
                vista,
                width=620,
                height=75,
                fg_color="white",
                corner_radius=25,
                border_width=1,
                border_color="#E0E0E0"
            )
            fondo_pdf_frame.pack()
            fondo_pdf_frame.pack_propagate(False)

            img_pdf = resize_image_proportionally("adobe", 50)
            image_label = ctk.CTkLabel(fondo_pdf_frame, image=img_pdf, bg_color="transparent", text="")
            image_label.image = img_pdf
            image_label.pack(side="left", padx=20)

            pdf_frame = ctk.CTkFrame(fondo_pdf_frame, fg_color="transparent")
            pdf_frame.pack(side="left", expand=True, anchor="w")

            filename = os.path.basename(self.document_path)
            folder_path = os.path.dirname(self.document_path)

            label_title = ctk.CTkLabel(
                pdf_frame,
                text=filename,
                text_color="#111111",
                font=("Inter", 18),
                fg_color="transparent",
                anchor="w"
            )
            label_title.pack(anchor="w")

            label_path = ctk.CTkLabel(
                pdf_frame,
                text=folder_path,
                text_color="#555555",
                font=("Inter", 14),
                fg_color="transparent",
                anchor="w"
            )
            label_path.pack(anchor="w")

        # Frame para el certificado (solo si hay certificado)
        if cert is not None:
            certificado_label = ctk.CTkLabel(vista, text="Certificado digital:",
                                        font=("Inter", 19), text_color="#111111")
            certificado_label.pack(anchor="w", padx=(30,0), pady=(40,15))

            datos_cert_container = ctk.CTkFrame(
                vista, 
                fg_color="#FFFFFF",
                corner_radius=25,
                border_width=1,
                border_color="#E0E0E0",
                width=620,
                height = 80
            )
            datos_cert_container.pack()
            datos_cert_container.pack_propagate(False)

            padding_frame = ctk.CTkFrame(
                datos_cert_container,
                fg_color="transparent",
                corner_radius=0
            )
            padding_frame.pack(pady=(9,0), padx=(1,0))

            from datetime import datetime
            certificado_row = create_certificate_row(
                lista_frame= padding_frame,
                row_count=0,
                cert_info=cert,
                fecha_firma=datetime.now().isoformat(),
                estado= 0 if success else 2,
                callback_volver_a= lambda: self.vista_resultado_firma(success, cert),
                separator=False
            )

        # Boton finalizar
        fin_btn = create_button(vista, "Finalizar", lambda: self.vista_inicial_autofirma())
        fin_btn.pack(pady=(50,0))

    # cert valido = 1 = no hace falta parametro, 2 = valido, 0 = no valido
    def vista_info_certificado(self, cert_data, fecha_firma, volver_a = None, cert_valido = 1):
        from frontend.compComunes import cert_data_list

        vista = crear_vista_nueva(self.root)
        
        titulo_label = ctk.CTkLabel(vista, text="Información sobre el certificado", font=("Inter", 25), fg_color="transparent")
        titulo_label.pack(pady=(40, 50))

        # Use the cert parameter instead of undefined certificado_path
        datos_list = cert_data_list(vista, cert_data, fecha_firma, cert_valido)
        datos_list.pack()
        
        # Detectar si volver_a es un método directo o una lambda
        if volver_a.__name__ == 'vista_resultado_firma':
            # Es vista_resultado_firma directamente, necesita argumentos
            volver_btn = create_button(vista, "Volver", 
                lambda: volver_a(cert_valido == 2, cert_data))
        else:
            # Es una lambda u otra función, llamar sin argumentos
            volver_btn = create_button(vista, "Volver", lambda: volver_a())
        volver_btn.pack(pady=40)

if __name__ == "__main__":
    # Iniciar aplicación
    root = TkinterDnD.Tk()
    set_base_dir(BASE_DIR)
    set_base_dir_back_firma(BASE_DIR)
    app = AutoFirmaApp(root)
    set_app_instance(app)
    set_app_instance_autofirma(app)
    register_protocol_handler()

    # Comprobar si se inicia para verificación automática, Verificar desde URI (autofirma://...)
    if len(sys.argv) > 1 and sys.argv[1] == "--verify" and len(sys.argv) > 2:
        uri = sys.argv[2]
        
        def verify_from_uri(uri):
            """Maneja la UI y llama al backend"""
            from backend.funcFirma import process_uri
            
            success, file_path = process_uri(uri)
            if not success:
                messagebox.showerror("Error", "No se pudo verificar el documento. Por favor asegúrese de que el PDF esté abierto y sea accesible.")
                
            app.document_path = file_path
            app.verify_signatures()

        # Programar verificación para después de iniciar la UI
        root.after(500, lambda: verify_from_uri(uri))
    
    root.mainloop()