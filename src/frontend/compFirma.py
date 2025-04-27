import tkinter as tk
import customtkinter as ctk # type: ignore
from backend.funcComunes import format_iso_display, log_message
from frontend.compComunes import resize_image_proportionally # type: ignore
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
    container.pack(anchor="w", pady=(10, 0))
    
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

def create_drop_area(parent, text="Pulse el área y seleccione el documento o arrástrelo aquí", callback=None):
    from tkinterdnd2 import DND_FILES # type: ignore
    def open_file_dialog(event=None):
        from tkinter import filedialog
        file_path = filedialog.askopenfilename(
            title="Seleccionar archivo firmado",
            filetypes=[("Archivos PDF", "*.pdf")])
        if file_path:
            update_label(file_path)
            if callback:
                callback(file_path)

    def drop(event):
        path = event.data.strip('{}')
        if path.lower().endswith(".pdf"):
            update_label(path)
            if callback:
                callback(path)

    def update_label(file_path):
        from PIL import Image, ImageTk # type: ignore
        import os

        # Desconectar eventos del frame antes de limpiar
        frame_container.unbind("<Enter>")
        frame_container.unbind("<Leave>")
        
        # Limpia el frame antes de añadir elementos nuevos
        for widget in frame_container.winfo_children():
            widget.destroy()

        # Label "Documento seleccionado"
        label_info = tk.Label(
            frame_container,
            text="Documento seleccionado:",
            fg="#111111",
            font=("Inter", 16, "bold"),
            bg="white",
            anchor="w",
            justify="left"
        )
        label_info.pack(anchor="w", padx=20, pady=(10, 0))

        # Contenedor horizontal: imagen + info PDF
        content_frame = tk.Frame(frame_container, bg="white")
        content_frame.pack(fill="x", padx=20, pady=10)

        # Imagen de Adobe
        img_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "img", "adobe.png")
        img = Image.open(img_path)
        img = img.resize((57, 57))
        img_tk = ImageTk.PhotoImage(img)

        image_label = tk.Label(content_frame, image=img_tk, bg="white")
        image_label.image = img_tk
        image_label.pack(side="left", padx=(0, 10))

        # Título y ruta
        pdf_frame = tk.Frame(content_frame, bg="white")
        pdf_frame.pack(side="left", fill="x", expand=True)

        filename = os.path.basename(file_path)
        folder_path = os.path.dirname(file_path)

        label_title = tk.Label(
            pdf_frame,
            text=filename,
            fg="#111111",
            font=("Inter", 15),
            bg="white",
            anchor="w"
        )
        label_title.pack(anchor="w")

        label_path = tk.Label(
            pdf_frame,
            text=folder_path,
            fg="#555555",
            font=("Inter", 11),
            bg="white",
            anchor="w"
        )
        label_path.pack(anchor="w")

        # Vincular nuevos eventos al contenedor después de actualizar
        frame_container.bind("<Enter>", lambda e: frame_container.config(bg="#FAFAFA"))
        frame_container.bind("<Leave>", lambda e: frame_container.config(bg="white"))
        
        # Actualizar todos los elementos de fondo cuando se pasa el ratón
        def update_all_bg_enter(event):
            frame_container.config(bg="#FAFAFA")
            for child in frame_container.winfo_children():
                if isinstance(child, tk.Label) or isinstance(child, tk.Frame):
                    child.config(bg="#FAFAFA")
                if isinstance(child, tk.Frame):
                    for grandchild in child.winfo_children():
                        if isinstance(grandchild, tk.Label) or isinstance(grandchild, tk.Frame):
                            grandchild.config(bg="#FAFAFA")
                        if isinstance(grandchild, tk.Frame):
                            for great_grandchild in grandchild.winfo_children():
                                if isinstance(great_grandchild, tk.Label):
                                    great_grandchild.config(bg="#FAFAFA")
        
        def update_all_bg_leave(event):
            frame_container.config(bg="white")
            for child in frame_container.winfo_children():
                if isinstance(child, tk.Label) or isinstance(child, tk.Frame):
                    child.config(bg="white")
                if isinstance(child, tk.Frame):
                    for grandchild in child.winfo_children():
                        if isinstance(grandchild, tk.Label) or isinstance(grandchild, tk.Frame):
                            grandchild.config(bg="white")
                        if isinstance(grandchild, tk.Frame):
                            for great_grandchild in grandchild.winfo_children():
                                if isinstance(great_grandchild, tk.Label):
                                    great_grandchild.config(bg="white")
        
        frame_container.bind("<Enter>", update_all_bg_enter)
        frame_container.bind("<Leave>", update_all_bg_leave)

    # Crear el frame contenedor
    outer_container = ctk.CTkFrame(
        parent,
        width=620,
        height=260,
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
        height=240,
        bg="white",
        highlightthickness=0
    )
    frame_container.place(relx=0.5, rely=0.5, anchor="center")
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
        # Verificar si la etiqueta aún existe
        for widget in frame_container.winfo_children():
            if widget == label and widget.winfo_exists():
                label.config(bg="#FAFAFA")

    def on_leave(event):
        frame_container.config(bg="white")
        # Verificar si la etiqueta aún existe
        for widget in frame_container.winfo_children():
            if widget == label and widget.winfo_exists():
                label.config(bg="white")

    frame_container.bind("<Enter>", on_enter)
    frame_container.bind("<Leave>", on_leave)

    return frame_container

def create_certificate_list(parent, base_dir, firmas):
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

            estado = 0
            if not resultado["firma_valida"]:
                estado = 1
            elif not resultado["cert_valido"]:
                estado = 2
            elif not resultado["integridad_valida"]:
                estado = 3

            if estado == 0:
                valid_count += 1
            else:
                invalid_count += 1

            row_count = create_certificate_row(base_dir, lista_frame, row_count, firma_data, estado, APP_INSTANCE.verify_signatures)
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

def create_certificate_row(base_dir, lista_frame, row_count, firma, estado = 0, callback_volver_a = None):
    from frontend.compComunes import create_base_row

    def razon_error(motivo_error):
        if motivo_error == 1:
            return "La firma digital no es válida"
        elif motivo_error == 2:
            return "El certificado ha expirado o ha sido revocado"
        elif motivo_error == 3:
            return "La integridad del documento está comprometida"
        else:
            return "La firma no es válida"

    # Definir tamaños específicos para columnas
    column_sizes = [100, 300, 130, 40]  # Logo | Nombre + Estado | Fecha | Check //610

    cert_info = firma["certificado_autenticacion"]

    # Crear la fila base
    fila_container, next_row, _ = create_base_row(
        lista_frame=lista_frame,
        row_count=row_count,
        column_sizes=column_sizes,
        click_callback=lambda event, c=cert_info, f=firma.get("fecha_firma"), v=callback_volver_a: APP_INSTANCE.vista_info_certificado(c, f, v)
    )

    es_valida = not estado

    # --- Columna 0: logo del algoritmo ---
    img_algortimo = resize_image_proportionally(base_dir, cert_info["algoritmo"], 45)

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
    fecha_firma = firma.get("fecha", f"{format_iso_display(firma["fecha_firma"])}")
    fecha_label = ctk.CTkLabel(
        fila_container, 
        text=fecha_firma, 
        font=("Inter", 17),
        text_color="#555555"
    )
    fecha_label.grid(row=0, column=2, rowspan=2, pady=8, sticky="nsew")

    # --- Columna 3: icono de verificación ---
    img = resize_image_proportionally(base_dir, "tick" if es_valida else "error", 40)

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
