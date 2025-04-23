import tkinter as tk
import customtkinter as ctk # type: ignore
ctk.set_appearance_mode("light")


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
        file_path = filedialog.askopenfilename(filetypes=[("Archivos PDF", "*.pdf")])
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
        height=220,
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
        height=200,
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

def create_certificate_list(parent):
    """
    Crea una lista específica para mostrar certificados
    """
    from frontend.compComunes import create_base_list
    # Cargar datos simulados
    certificados = generar_certificados_simulados()
    
    # Definir función para procesar datos
    def procesar_certificados(lista_frame, datos):
        row_count = 0
        for cert in datos:
            row_count = create_certificate_row(lista_frame, row_count, cert)
        return row_count

    # Obtener la estructura base de la lista
    contenedor_principal = create_base_list(
        parent, 
        height=270,
        empty_message="No hay certificados disponibles.",
        process_data_function=procesar_certificados,
        data=certificados,
        max_visible_items=4
    )
    
    return contenedor_principal

def create_certificate_row(lista_frame, row_count, certificado):
    """
    Añade una fila con información de certificado al frame scrollable
    """
    from frontend.compComunes import create_base_row

    # Definir tamaños específicos para columnas de certificados
    column_sizes = [400, 180]  # Certificado, Algoritmo
    
    # Crear la fila base
    fila_container, next_row, logo_images = create_base_row(
        lista_frame=lista_frame,
        row_count=row_count,
        column_sizes=column_sizes,
        click_callback="mostrar_roumualdo"
    )
    
    # Título del certificado (columna 0)
    cert_label = ctk.CTkLabel(
        fila_container, 
        text=certificado["titulo"], 
        font=("Segoe UI", 13),
        text_color="#111111"
    )
    cert_label.grid(row=0, column=0, padx=15, pady=8, sticky="w")
    
    # Mostrar logo o nombre del algoritmo (columna 1)
    algoritmo = certificado["algoritmo"]
    if algoritmo in logo_images and logo_images[algoritmo]:
        logo_label = tk.Label(
            fila_container, 
            image=logo_images[algoritmo], 
            bg=fila_container["bg"]
        )
        logo_label.grid(row=0, column=1, padx=15, pady=8, sticky="w")
    else:
        alg_nombre = "SPHINCS+" if algoritmo == "sphincs" else "Dilithium"
        alg_label = ctk.CTkLabel(
            fila_container, 
            text=alg_nombre, 
            font=("Segoe UI", 12)
        )
        alg_label.grid(row=0, column=1, padx=15, pady=8, sticky="w")
    
    return next_row

def generar_certificados_simulados():
    """
    Genera datos de certificados simulados para pruebas
    """
    certificados = [
        {
            "titulo": "Certificado de Identidad Digital",
            "algoritmo": "dilithium",
            "fecha_emision": "2023-12-15"
        },
        {
            "titulo": "Certificado de Servidor Web",
            "algoritmo": "sphincs",
            "fecha_emision": "2024-01-10"
        },
                {
            "titulo": "Certificado de Servidor Web",
            "algoritmo": "sphincs",
            "fecha_emision": "2024-01-10"
        },
                {
            "titulo": "Certificado de Servidor Web",
            "algoritmo": "sphincs",
            "fecha_emision": "2024-01-10"
        },
        {
            "titulo": "Certificado de Firma de Código",
            "algoritmo": "dilithium",
            "fecha_emision": "2024-01-25"
        }
    ]
    return certificados