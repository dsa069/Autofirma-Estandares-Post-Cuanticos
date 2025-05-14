import tkinter as tk
import customtkinter as ctk # type: ignore
from backend.funcComunes import log_message

ctk.set_appearance_mode("light")

APP_INSTANCE = None  # Para guardar la referencia a la aplicación principal

# Función para establecer la instancia de la aplicación
def set_app_instance_autofirma(app):
    global APP_INSTANCE
    APP_INSTANCE = app
    log_message("entGenApp.log", f"APP_INSTANCE establecido: {APP_INSTANCE}")

def create_checkbox(parent, text):
    # Contenedor principal (transparente)
    container = ctk.CTkFrame(parent, fg_color="transparent")
    container.pack(pady=(10, 0))
    
    # Botón de sombra (más grande y oscuro)
    shadow = ctk.CTkButton(
        container,
        text="",
        width=22,  # Más grande para mejor efecto
        height=22,  # Más grande para mejor efecto
        corner_radius=5,
        fg_color="#777777",
        hover=0,
        border_width=0,
        state="disabled"
    )
    shadow.place(x=2, y=4) 

    checkbox = ctk.CTkCheckBox(
        container,
        text=text,
        font=("Inter", 15),
        text_color="#111111",
        checkbox_height=20,
        checkbox_width=20,
        corner_radius=5,
        border_width=10,
        fg_color="#FFFFFF",
        hover= 0,
        border_color="#FFFFFF",
        checkmark_color="#28A745"
    )
    # Mayor offset para hacer visible la sombra
    checkbox.grid(row=0, column=0, padx=(4, 0), pady=(0, 4))  # Aumentar de 3 a 4
    
    # Asegurar que el checkbox esté por encima de la sombra
    checkbox.lift()
    
    # Agregar los métodos del checkbox al contenedor
    container.get = checkbox.get
    container.select = checkbox.select
    container.deselect = checkbox.deselect
    
    return container

def create_drag_drop_area(parent, text, callback=None, height=260, 
                         file_filter=None, dialog_title="Seleccionar archivo", 
                         initial_dir=None, custom_content_renderer=None,
                         content_label=None, image_provider=None, center_content=False):
    """
    Método genérico para crear áreas de arrastrar y soltar.
    
    Parámetros:
    - parent: Widget padre
    - text: Texto a mostrar inicialmente
    - callback: Función a llamar cuando se selecciona un archivo
    - height: Altura del contenedor
    - file_filter: Tupla (descripción, patrón) para filtrar archivos
    - dialog_title: Título del diálogo de selección
    - initial_dir: Directorio inicial para el diálogo
    - custom_content_renderer: Función personalizada para renderizar el contenido
    - content_label: Texto de etiqueta de contenido (ej: "Documento seleccionado:")
    - image_provider: Función que proporciona la imagen adecuada para el archivo
    """
    from tkinterdnd2 import DND_FILES # type: ignore
    
    def open_file_dialog(event=None):
        from tkinter import filedialog
        import os
        
        # Obtener directorio inicial
        init_dir = initial_dir() if callable(initial_dir) else initial_dir
        if init_dir is None:
            init_dir = os.path.join(os.path.expanduser("~"), "Desktop")
        
        file_path = filedialog.askopenfilename(
            title=dialog_title,
            initialdir=init_dir,
            filetypes=[file_filter] if file_filter else []
        )
        
        if file_path:
            update_label(file_path)
            if callback:
                callback(file_path)

    def drop(event):
        path = event.data.strip('{}')
        if is_valid_file(path):
            update_label(path)
            if callback:
                callback(path)
    
    def is_valid_file(path):
        import os
        if file_filter:
            desc, pattern = file_filter
            if pattern.startswith("*"):
                # Es una extensión
                if not path.lower().endswith(pattern[1:]):
                    return False
            elif "." in pattern:
                # Es un patrón específico
                filename = os.path.basename(path)
                import fnmatch
                return fnmatch.fnmatch(filename, pattern)
        return True

    def update_label(file_path):
        import os
        
        # Desconectar eventos del frame antes de limpiar
        frame_container.unbind("<Enter>")
        frame_container.unbind("<Leave>")
        
        # Limpia el frame antes de añadir elementos nuevos
        for widget in frame_container.winfo_children():
            widget.destroy()
            
        if custom_content_renderer:
            custom_content_renderer(frame_container, file_path)
        else:
            # Crear un frame contenedor para centrado si es necesario
            if center_content:
                # Usar pack con expand=True para centrado vertical natural
                content_container = tk.Frame(frame_container, bg="white")
                content_container.pack(fill="x", expand=True)
                target_frame = content_container
            else:
                target_frame = frame_container
            
            # Renderizar contenido genérico (estructura común)
            if content_label:
                # Label "Contenido seleccionado"
                label_info = tk.Label(
                    target_frame,
                    text=content_label,
                    fg="#111111",
                    font=("Inter", 16, "bold"),
                    bg="white",
                    anchor="w",
                    justify="left"
                )
                label_info.pack(anchor="w", padx=20, pady=(10, 0))
            
            # Contenedor horizontal: imagen + info
            content_frame = tk.Frame(target_frame, bg="white")
            content_frame.pack(fill="x", padx= (10,0) if center_content else (20,0) , pady=10)
            
            # Imagen (si hay proveedor de imágenes)
            if image_provider:
                image = image_provider(file_path)
                if image:
                    image_label = ctk.CTkLabel(
                        content_frame, 
                        image=image,
                        text="",
                        fg_color="white"
                    )
                    image_label.pack(side="left", padx=(0, 10))
            
            # Título y ruta
            info_frame = tk.Frame(content_frame, bg="white")
            info_frame.pack(side="left", fill="x", expand=True)
            
            filename = os.path.basename(file_path)
            folder_path = os.path.dirname(file_path)
            
            label_title = tk.Label(
                info_frame,
                text=filename,
                fg="#111111",
                font=("Inter", 15),
                bg="white",
                anchor="w"
            )
            label_title.pack(anchor="w")
            
            label_path = tk.Label(
                info_frame,
                text=folder_path,
                fg="#555555",
                font=("Inter", 11),
                bg="white",
                anchor="w"
            )
            label_path.pack(anchor="w")
            
        # Vincular nuevos eventos al contenedor
        frame_container.bind("<Enter>", lambda e: frame_container.config(bg="#FAFAFA"))
        frame_container.bind("<Leave>", lambda e: frame_container.config(bg="white"))
        label_title.bind("<Button-1>", open_file_dialog)
        label_path.bind("<Button-1>", open_file_dialog)
        
        def update_all_bg_enter(event):
            frame_container.config(bg="#FAFAFA")
            for child in frame_container.winfo_children():
                # Determinar si es un widget CTk o un widget tk estándar
                if "CTk" in child.__class__.__name__:  # Es un widget CustomTkinter
                    try:
                        child.configure(fg_color="#FAFAFA")
                    except Exception:
                        pass
                elif isinstance(child, (tk.Label, tk.Frame)):  # Es un widget tk estándar
                    child.config(bg="#FAFAFA")
                        
                # Manejar widgets anidados de primer nivel
                if isinstance(child, tk.Frame):
                    for grandchild in child.winfo_children():
                        if "CTk" in grandchild.__class__.__name__:  # Es un widget CustomTkinter
                            try:
                                grandchild.configure(fg_color="#FAFAFA")
                            except Exception:
                                pass
                        elif isinstance(grandchild, (tk.Label, tk.Frame)):  # Es un widget tk estándar
                            grandchild.config(bg="#FAFAFA")
                                
                        # Manejar widgets anidados de segundo nivel
                        if isinstance(grandchild, tk.Frame):
                            for great_grandchild in grandchild.winfo_children():
                                if "CTk" in great_grandchild.__class__.__name__:  # Es un widget CustomTkinter
                                    try:
                                        great_grandchild.configure(fg_color="#FAFAFA")
                                    except Exception:
                                        pass
                                elif isinstance(great_grandchild, tk.Label):  # Es un widget tk estándar
                                    great_grandchild.config(bg="#FAFAFA")
        
        def update_all_bg_leave(event):
            frame_container.config(bg="white")
            for child in frame_container.winfo_children():
                # Determinar si es un widget CTk o un widget tk estándar
                if "CTk" in child.__class__.__name__:  # Es un widget CustomTkinter
                    try:
                        child.configure(fg_color="white")
                    except Exception:
                        pass
                elif isinstance(child, (tk.Label, tk.Frame)):  # Es un widget tk estándar
                    child.config(bg="white")
                        
                # Manejar widgets anidados de primer nivel
                if isinstance(child, tk.Frame):
                    for grandchild in child.winfo_children():
                        if "CTk" in grandchild.__class__.__name__:  # Es un widget CustomTkinter
                            try:
                                grandchild.configure(fg_color="white")
                            except Exception:
                                pass
                        elif isinstance(grandchild, (tk.Label, tk.Frame)):  # Es un widget tk estándar
                            grandchild.config(bg="white")
                                
                        # Manejar widgets anidados de segundo nivel
                        if isinstance(grandchild, tk.Frame):
                            for great_grandchild in grandchild.winfo_children():
                                if "CTk" in great_grandchild.__class__.__name__:  # Es un widget CustomTkinter
                                    try:
                                        great_grandchild.configure(fg_color="white")
                                    except Exception:
                                        pass
                                elif isinstance(great_grandchild, tk.Label):  # Es un widget tk estándar
                                    great_grandchild.config(bg="white")

        # Vincular eventos de clic a todos los elementos
        frame_container.bind("<Button-1>", open_file_dialog)
        for widget in frame_container.winfo_children():
            widget.bind("<Button-1>", open_file_dialog)
            if isinstance(widget, tk.Frame):
                for child in widget.winfo_children():
                    child.bind("<Button-1>", open_file_dialog)
        
        frame_container.bind("<Enter>", update_all_bg_enter)
        frame_container.bind("<Leave>", update_all_bg_leave)

    # Crear el frame contenedor
    outer_container = ctk.CTkFrame(
        parent,
        width=620,
        height=height,
        corner_radius=25,
        fg_color="#FFFFFF",
        border_width=1,
        border_color="#E0E0E0"
    )
    outer_container.pack(pady=10)
    outer_container.pack_propagate(False)
    
    # Crear el frame contenedor real encima (sin bordes)
    frame_container = tk.Frame(
        outer_container,
        width=600,
        height=height-20,
        bg="white",
        highlightthickness=0
    )
    frame_container.pack(expand=True)
    frame_container.pack_propagate(False)

    # Crear la etiqueta inicial
    label = tk.Label(
        frame_container,
        text=text,
        fg="#555555",
        font=("Inter", 16),
        bg="white",
        wraplength=580,
        justify="center"
    )
    label.pack(expand=True)

    # Vincular eventos al frame y la etiqueta
    frame_container.bind("<Button-1>", open_file_dialog)
    label.bind("<Button-1>", open_file_dialog)

    # Configurar el área para soltar archivos
    frame_container.drop_target_register(DND_FILES)
    frame_container.dnd_bind('<<Drop>>', drop)

    # Eventos de entrada y salida del mouse para el estado inicial
    def on_enter(event):
        frame_container.config(bg="#FAFAFA")
        for widget in frame_container.winfo_children():
            if widget == label and widget.winfo_exists():
                label.config(bg="#FAFAFA")

    def on_leave(event):
        frame_container.config(bg="white")
        for widget in frame_container.winfo_children():
            if widget == label and widget.winfo_exists():
                label.config(bg="white")

    frame_container.bind("<Enter>", on_enter)
    frame_container.bind("<Leave>", on_leave)

    return frame_container

def create_pdf_area(parent, text="Pulse el área y seleccione el documento o arrástrelo aquí", callback=None):
    """Crea un área para arrastrar y soltar documentos PDF"""
    import os
    from PIL import Image, ImageTk # type: ignore
    
    # 1. Corregir get_pdf_image para usar CTkImage
    def get_pdf_image(file_path):
        """Obtiene la imagen de Adobe para un PDF"""
        img_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "img", "adobe.png")
        img = Image.open(img_path)
        # Usar CTkImage en lugar de ImageTk.PhotoImage
        return ctk.CTkImage(light_image=img, size=(57, 57))
    
    return create_drag_drop_area(
        parent=parent,
        text=text,
        callback=callback,
        height=260,
        file_filter=("Archivos PDF", "*.pdf"),
        dialog_title="Seleccionar documento PDF",
        initial_dir=os.path.join(os.path.expanduser("~"), "Desktop"),
        content_label="Documento seleccionado:",
        image_provider=get_pdf_image,
        center_content=False  # No centrar verticalmente (comportamiento por defecto)
    )

def create_cert_area(parent, text="Pulse el area y seleccione el certificado de firma a utilizar", callback=None):
    """Crea un área para arrastrar y soltar certificados digitales"""
    import os
    
    def get_certs_dir():
        """Obtiene el directorio de certificados"""
        user_home = os.path.expanduser("~")
        certs_folder = os.path.join(user_home, "certificados_postC")
        
        # Verificar si la carpeta existe
        if not os.path.exists(certs_folder):
            log_message("firmaApp.log", "Error: No se encuentra la carpeta certificados_postC")
        
        return certs_folder
    
    def get_cert_image(file_path):
        """Obtiene la imagen del algoritmo para un certificado"""
        from frontend.compComunes import resize_image_proportionally 

        filename = os.path.basename(file_path)
        nombre_sin_prefijo = filename[len("certificado_digital_firmar_"):].lower()
        
        algoritmo = "dilithium" if "dilithium" in nombre_sin_prefijo else "sphincs"
        return resize_image_proportionally(algoritmo.capitalize(), 50)
    
    return create_drag_drop_area(
        parent=parent,
        text=text,
        callback=callback,
        height=120,  # Altura exacta como en el código original
        file_filter=("Certificados", "certificado_digital_firmar_*.json"),
        dialog_title="Seleccionar certificado",
        initial_dir=get_certs_dir,
        image_provider=get_cert_image,
        center_content=True  # Mantener centrado vertical
    )

def create_certificate_list(parent, firmas):
    """
    Crea una lista específica para mostrar certificados
    """
    from frontend.compComunes import create_base_list

    valid_count = 0
    invalid_count = 0    
    # Definir función para procesar datos
    def procesar_certificados(lista_frame, datos):
        nonlocal valid_count, invalid_count
        row_count = 0
        for resultado in datos:
            #i = resultado["indice"]
            firma_data = resultado["firma_data"]
            cert_info = firma_data["certificado_autenticacion"]
            fecha_firma = firma_data.get("fecha_firma")

            estado = 0
            if not resultado["integridad_valida"]:
                estado = 3
            elif not resultado["cert_valido"]:
                estado = 2
            elif not resultado["firma_valida"]:
                estado = 1

            if estado == 0:
                valid_count += 1
            else:
                invalid_count += 1

            row_count = create_certificate_row(lista_frame, row_count, cert_info, fecha_firma, estado, APP_INSTANCE.verify_signatures)
        return row_count

    # Obtener la estructura base de la lista
    contenedor_principal = create_base_list(
        parent, 
        height=210,
        empty_message="No hay certificados disponibles.",
        process_data_function=procesar_certificados,
        data=firmas,
        max_visible_items=2
    )
    
    return contenedor_principal, valid_count, invalid_count

def create_certificate_row(lista_frame, row_count, cert_info, fecha_firma, estado = 0, callback_volver_a = None, separator = True):
    from backend.funcComunes import format_iso_display
    from frontend.compComunes import create_base_row, resize_image_proportionally

    def razon_error(motivo_error):
        if motivo_error == 1:
            return "La firma digital no es válida"
        elif motivo_error == 2:
            return "El certificado ha expirado o ha sido alterado"
        elif motivo_error == 3:
            return "La integridad del documento está comprometida"
        else:
            return "La firma no es válida"

    # Definir tamaños específicos para columnas
    column_sizes = [100, 300, 130, 40]  # Logo | Nombre + Estado | Fecha | Check //610

        # Determinar el valor correcto de cert_valido
    if callback_volver_a and callback_volver_a.__name__ == 'verify_signatures':
        # Para certificados que vienen de verify_signatures, usamos 1 (el valor neutral)
        cert_valido_value = 1
    else:
        # Para certificados de vista_resultado_firma, usamos 0 o 2 según el estado
        cert_valido_value = 2 if estado == 0 else 0

    # Crear la fila base
    fila_container, next_row = create_base_row(
        lista_frame=lista_frame,
        row_count=row_count,
        column_sizes=column_sizes,
        click_callback=lambda event, c=cert_info, f=fecha_firma, v=callback_volver_a, e=estado: 
        APP_INSTANCE.vista_info_certificado(c, f, v, cert_valido_value),
        separator=separator
    )

    es_valida = not estado

    # --- Columna 0: logo del algoritmo ---
    img_algortimo = resize_image_proportionally(cert_info["algoritmo"], 45)

    logo_label = ctk.CTkLabel(
        fila_container,
        image=img_algortimo,
        text="", 
        bg_color=fila_container["bg"]
    )
    logo_label.image = img_algortimo
    logo_label.grid(row=0, column=0, rowspan=2, pady=8, sticky="nsew")

    # --- Columna 1: nombre y dni, estado de certificado ---
    nombre_dni_label = ctk.CTkLabel(
        fila_container, 
        text=f"{cert_info['nombre']} - {cert_info['dni']}", 
        font=("Inter", 17),
        text_color="#111111"
    )
    nombre_dni_label.grid(row=0, column=1, padx=(10,0), sticky="w")

    estado_certificado = "El certificado es válido" if es_valida else f"{razon_error(estado)}"
    estado_label = ctk.CTkLabel(
        fila_container, 
        text=estado_certificado, 
        font=("Inter", 13),
        text_color="#15984C" if es_valida else "#CB1616"
    )
    estado_label.grid(row=1, column=1, padx=(10,0), sticky="w")

    # --- Columna 2: fecha ---
    fecha_firma_display = f"{format_iso_display(fecha_firma)}"
    fecha_label = ctk.CTkLabel(
        fila_container, 
        text=fecha_firma_display, 
        font=("Inter", 17),
        text_color="#555555"
    )
    fecha_label.grid(row=0, column=2, rowspan=2, pady=8, sticky="nsew")

    # --- Columna 3: icono de verificación ---
    img = resize_image_proportionally("tick" if es_valida else "error", 40)

    if img:
        check_label = ctk.CTkLabel(
            fila_container,
            image=img,
            text="", 
            bg_color=fila_container["bg"]
        )
        check_label.image = img
        check_label.grid(row=0, column=3, rowspan=2, padx=5, pady=8, sticky="e")

    return next_row
