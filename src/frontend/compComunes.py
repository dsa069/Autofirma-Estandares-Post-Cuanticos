import tkinter as tk
from tkinter import filedialog
import customtkinter as ctk
import os
from PIL import Image, ImageTk
from tkinterdnd2 import DND_FILES, TkinterDnD
from backend.funcComunes import log_message

# Variable global para mantener referencias a las imágenes
LOGO_IMAGES = {}  # Mover a nivel global
APP_INSTANCE = None  # Para guardar la referencia a la aplicación principal

# Función para establecer la instancia de la aplicación
def set_app_instance(app):
    global APP_INSTANCE
    APP_INSTANCE = app

ctk.set_appearance_mode("light")

def center_window(root):
    """Centra la ventana en la pantalla"""
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')

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

def create_button(parent, text, command=None, width=110):
    """
    Crea un botón moderno con efecto de sombra proyectada
    """
    # Contenedor principal (transparente)
    container = ctk.CTkFrame(parent, fg_color="transparent")
    
    # Botón de sombra (más grande y oscuro)
    shadow = ctk.CTkButton(
        container,
        text="",  # Sin texto
        width=width,
        height=30,
        corner_radius=5,
        fg_color="#777777",  # Color oscuro para la sombra
        hover=0,  # La sombra no cambia
        border_width=0,
        state="disabled"  # No interactivo
    )
    shadow.grid(row=0, column=0, padx=0, pady=0)
    
    # Botón principal (ligeramente desplazado)
    button = ctk.CTkButton(
        container,
        text=text,
        command=command,
        width=width,
        height=30,
        corner_radius=5,
        border_width=1,
        border_color="#999999",
        fg_color="#DCDCDC",
        text_color="#111111",
        hover_color="#BBBBBB",
        font=("Inter", 15),
    )
    # Posicionar con offset para crear efecto de sombra
    button.grid(row=0, column=0, padx=(0, 4), pady=(0, 4))
    
    # Asegurar que el botón esté por encima de la sombra
    button.lift()
    
    return container

def create_text_field_with_title(parent, text, placeholder="", width=450):
    contenedor = ctk.CTkFrame(parent, fg_color="transparent")
    contenedor.pack(anchor="w", pady=(10, 10))  # Alineado a la izquierda

    label = ctk.CTkLabel(contenedor, text=text, font=("Inter", 17), text_color="#111111")
    label.pack(anchor="w")

    entrada = create_text_field(contenedor, placeholder, width)
    entrada.pack(anchor="w", pady=(5, 0))

    return entrada

def create_text_field(parent, placeholder = "", width=450):
    entrada = ctk.CTkEntry(
        parent,
        placeholder_text=placeholder,
        width=width,
        height=33,
        font=("Inter", 12),
        fg_color="#FFFFFF",
        placeholder_text_color="#555555",  # Gris claro
        border_color="#E0E0E0",
        border_width=1, 
        corner_radius=10
    )
    entrada.pack(padx=(10,0))
    return entrada

def create_dropdown_with_text(parent, text, opciones = [], placeholder = ""):
    contenedor = ctk.CTkFrame(parent, fg_color="transparent")
    contenedor.pack(anchor="w", pady=(10, 10))  # Alineado a la izquierda

    label = ctk.CTkLabel(contenedor, text=text, font=("Inter", 17), text_color="#111111")
    label.pack(anchor="w")

    entrada = create_dropdown(contenedor, opciones, placeholder)

    return entrada

def create_dropdown(parent, opciones = [], placeholder = ""):
    # Contenedor principal (transparente)
    container = ctk.CTkFrame(parent, fg_color="transparent")
    container.pack(anchor="w", padx=(10, 0)) 
    
    # Frame con bordes para simular bordes del dropdown
    border_frame = ctk.CTkFrame(
        container,
        width=304,
        height=38,
        corner_radius=10,
        fg_color="transparent",  # Transparente
        border_width=1,          # Borde visible
        border_color="#E0E0E0"   # Color claro para el borde
    )
    border_frame.grid(row=0, column=0, padx=0, pady=0)
    border_frame.grid_propagate(False)  # Mantener tamaño fijo
    

    combo = ctk.CTkOptionMenu(
        master=container,
        values=opciones,
        font=("Inter", 13),
        width=300,
        height=33,
        dropdown_font=("Inter", 13),
        fg_color="#FFFFFF",
        button_color="#FFFFFF",     # fondo de la flecha
        button_hover_color="#E0E0E0",
        text_color="#555555",
        dropdown_fg_color="#FFFFFF",
        dropdown_text_color="#333333",
        corner_radius=10,
        anchor="w",
        dropdown_hover_color="#E0E0E0",
    )

    combo.set(placeholder)
    # Posicionar con offset para crear efecto de sombra
    combo.place(relx=0.5, rely=0.5, anchor="center")     
    # Asegurar que el botón esté por encima de la sombra
    combo.lift()

    return combo

def create_base_list(parent, height=270, empty_message=None, process_data_function=None, data=None, headers=None, column_sizes=None, max_visible_items=1):
    """
    Crea un esqueleto básico para cualquier lista con estilo consistente.
    
    Args:
        parent: Widget padre
        height: Altura del contenedor
        empty_message: Mensaje a mostrar cuando la lista está vacía
        process_data_function: Función para procesar los datos y crear filas
        data: Datos a procesar para la lista
        headers: Encabezados de la lista
        column_sizes: Tamaños de las columnas encabezado
    """

    # Cargar imágenes si no están cargadas
    cargar_logos_algoritmos()

    # Frame contenedor principal
    contenedor_principal = ctk.CTkFrame(
        parent, 
        fg_color="#FFFFFF",
        corner_radius=25,
        border_width=1,
        border_color="#E0E0E0",
        width=620, 
        height=height
    )
    contenedor_principal.pack_propagate(False)  # Mantener tamaño fijo
    
    # Configurar encabezados si se proporcionan
    if headers and column_sizes:
        # Frame para encabezados (no scrollable)
        header_frame = ctk.CTkFrame(contenedor_principal, fg_color="#FFFFFF", corner_radius=0)
        header_frame.pack(fill="x", padx=10, pady=(10, 0))

        setup_list_headers(header_frame, headers, column_sizes)

        linea_divisora = tk.Frame(contenedor_principal, height=1, bg="#111111")
        linea_divisora.pack(fill="x", padx=15, pady=(2, 0))
    
    # Frame scrollable para elementos
    lista_frame = ctk.CTkScrollableFrame(
        contenedor_principal, 
        fg_color="#FFFFFF",
        corner_radius=0,
        border_width=0,
        width=620, 
        height=height-60,
        scrollbar_button_color="#DDDDDD",
    )
    lista_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Guardar mensaje de vacío para usar más tarde
    if empty_message:
        contenedor_principal.empty_message = empty_message
    
    # Procesar los datos si se proporcionan
    row_count = 0
    if process_data_function and data:
        row_count = process_data_function(lista_frame, data)
    
    # Condicionales para gestionar el separador y mensaje vacío
    if row_count > 0:
        eliminar_ultimo_separador(lista_frame, row_count)
    elif empty_message:
        mostrar_mensaje_vacio(lista_frame, empty_message)
    
    # Modificar el scrollbar si hay pocos elementos
    num_elementos = row_count // 2
    if num_elementos <= max_visible_items:
        def hide_scrollbar():
            # En CustomTkinter 5.x, el scrollbar se accede así:
            if hasattr(lista_frame, '_scrollbar'):
                lista_frame._scrollbar.configure(width=0)  # Hacer invisible manteniendo funcionalidad
        
        # Aplicar después de que se renderice completamente
        lista_frame.after(10, hide_scrollbar)

    return contenedor_principal

def create_key_list(parent):
    # Cargar datos de claves
    from backend.funcEntGen import cargar_claves_entidad, clasificar_claves_por_estado
    
    SK_ENTIDAD_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sk_entidad.json")
    PK_ENTIDAD_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pk_entidad.json")
    claves_disponibles = cargar_claves_entidad(SK_ENTIDAD_PATH, PK_ENTIDAD_PATH)
    claves_ordenadas = clasificar_claves_por_estado(claves_disponibles)
    
    # Definir función para procesar datos
    def procesar_claves(lista_frame, datos):
        row_count = 0
        for algoritmo, clave, es_caducada, es_futura in datos:
            row_count = create_key_row(lista_frame, row_count, algoritmo, clave, es_caducada, es_futura)
        return row_count
    
    # Definir encabezados específicos para claves
    encabezados = ["Algoritmo", "Título", "Clave Pública", "Período de Validez"]
    column_sizes = [80, 180, 120, 220]  # Tamaños por columna

    # Obtener la estructura base de la lista
    contenedor_principal = create_base_list(
        parent, 
        height=270,
        empty_message="No hay claves disponibles. Genera una nueva clave con el botón superior.",
        process_data_function=procesar_claves,
        data=claves_ordenadas,
        headers=encabezados,
        column_sizes=column_sizes,
        max_visible_items=4
    )
        
    return contenedor_principal

def create_certificate_list(parent):
    """
    Crea una lista específica para mostrar certificados
    """
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

def setup_list_headers(header_frame, headers, column_sizes):
    """
    Configura los encabezados de la lista y sus tamaños.
    
    Args:
        header_frame: Frame donde colocar los encabezados
        headers: Lista de textos para los encabezados
        column_sizes: Lista de tamaños para cada columna
    """
    # Configurar columnas con tamaños específicos
    for i, size in enumerate(column_sizes):
        header_frame.grid_columnconfigure(i, minsize=size)
    
    # Crear encabezados
    for i, texto in enumerate(headers):
        label = ctk.CTkLabel(
            header_frame, 
            text=texto, 
            font=("Segoe UI", 14, "bold"), 
            text_color="#111111",
            anchor="center",
            justify="center"
        )
        label.grid(row=0, column=i, padx=10, pady=5, sticky="ew")

def cargar_logos_algoritmos():
    """Carga las imágenes de logos de algoritmos si no están cargadas"""
    global LOGO_IMAGES
    
    if not LOGO_IMAGES:
        img_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "img")
        
        try:
            sphincs_path = os.path.join(img_path, "Sphincs.png")
            dilithium_path = os.path.join(img_path, "Dilithium.png")
            
            if os.path.exists(sphincs_path):
                sphincs_logo = Image.open(sphincs_path)
                sphincs_logo = sphincs_logo.resize((60, 35), Image.LANCZOS)
                LOGO_IMAGES["sphincs"] = ImageTk.PhotoImage(sphincs_logo)
            
            if os.path.exists(dilithium_path):
                dilithium_logo = Image.open(dilithium_path)
                dilithium_logo = dilithium_logo.resize((60, 30), Image.LANCZOS)
                LOGO_IMAGES["dilithium"] = ImageTk.PhotoImage(dilithium_logo)
                
        except Exception as e:
            log_message("entGenApp.log", f"Error al cargar logos: {e}")

def mostrar_mensaje_vacio(lista_frame, mensaje):
    """Muestra un mensaje cuando la lista está vacía"""
    mensaje_label = ctk.CTkLabel(
        lista_frame, 
        text=mensaje, 
        font=("Segoe UI", 12, "italic"),
        text_color="#757575"
    )
    mensaje_label.grid(row=0, column=0, columnspan=4, padx=20, pady=30)

def eliminar_ultimo_separador(lista_frame, row_count):
    """Elimina el último separador para mejorar la estética"""
    for widget in lista_frame.winfo_children():
        if isinstance(widget, tk.Frame) and widget.winfo_height() == 1:
            # Verificar si el widget usa grid y tiene información de fila
            grid_info = widget.grid_info()
            if grid_info and 'row' in grid_info:
                if int(grid_info["row"]) == row_count-1:
                    widget.destroy()
                    break

def create_base_row(lista_frame, row_count, column_sizes, click_callback=None, is_disabled=False):
    """
    Crea una fila base con estructura consistente para cualquier lista.
    
    Args:
        lista_frame: Frame scrollable donde se coloca la fila
        row_count: Número de fila actual
        column_sizes: Lista con los anchos para cada columna
        click_callback: Función a llamar cuando se hace clic en la fila
        is_disabled: Indica si la fila está deshabilitada (visual)
        
    Returns:
        tuple: (fila_container, row_count)
    """
    # Color de fondo según el estado
    color_fondo = "#F5F5F5" if is_disabled else "#FFFFFF"
    column_count = len(column_sizes)

    # Contenedor de la fila
    fila_container = tk.Frame(lista_frame, bg=color_fondo)
    fila_container.grid(row=row_count, column=0, columnspan=column_count, 
                       sticky="ew", padx=5, pady=2)
    
    # Configurar el tamaño de las columnas
    for i, size in enumerate(column_sizes):
        fila_container.grid_columnconfigure(i, minsize=size)
    
    # Lista para almacenar widgets que tienen comportamiento específico
    fila_container.special_widgets = []

    # Crear función de callback si se proporcionó un nombre de método
    if isinstance(click_callback, str):
        method_name = click_callback
        def generated_callback(event=None):
            global APP_INSTANCE
            if APP_INSTANCE and hasattr(APP_INSTANCE, method_name):
                getattr(APP_INSTANCE, method_name)()
            return "break"
        actual_callback = generated_callback
    else:
        actual_callback = click_callback
    
    # Configurar interactividad
    if not is_disabled and actual_callback:
        fila_container.configure(cursor="hand2")
        fila_container.bind("<Button-1>", actual_callback)
        
        # Hacer lo mismo para los hijos que se añadirán después
        def bind_to_children(event=None):
            for child in fila_container.winfo_children():
                # Solo vincular si no es un widget especial
                if child not in fila_container.special_widgets:
                    child.bind("<Button-1>", actual_callback)
                    
                # Revisar widgets anidados (como el frame de fechas)
                if isinstance(child, tk.Frame) or isinstance(child, ctk.CTkFrame):
                    for grandchild in child.winfo_children():
                        grandchild.bind("<Button-1>", actual_callback)
        
        # Vincular después de que se hayan creado los widgets hijos
        fila_container.bind("<Map>", bind_to_children)
    
    # Añadir línea divisoria después del elemento
    linea_divisora = tk.Frame(lista_frame, height=1, bg="#DDDDDD")
    linea_divisora.grid(row=row_count+1, column=0, columnspan=column_count, 
                       sticky="ew", padx=25, pady=2)
    
    return fila_container, row_count + 2  # +2 para la fila y la línea

def create_key_row(lista_frame, row_count, algoritmo, clave, es_caducada=False, es_futura=False):
    """
    Añade una fila con información de clave al frame scrollable
    """
    # Definir tamaños específicos para columnas de claves
    column_sizes = [80, 175, 150, 190]  # Algoritmo, Título, PK, Período
    
    # Crear la fila base
    fila_container, next_row = create_base_row(
        lista_frame=lista_frame,
        row_count=row_count,
        column_sizes=column_sizes,
        click_callback="generar_clave_UI",
        is_disabled=es_caducada
    )
    
    # Fechas de validez
    try:
        from datetime import datetime
        
        fecha_exp = datetime.fromisoformat(clave["fecha_expedicion"])
        fecha_cad = datetime.fromisoformat(clave["fecha_caducidad"])
        
        # Formatear fechas para visualización
        fecha_exp_str = fecha_exp.strftime("%d/%m/%Y")
        fecha_cad_str = fecha_cad.strftime("%d/%m/%Y")
        
        # Colores según estado
        color_cad = "#CB1616" if es_caducada else "#111111"  # Rojo si caducada
        color_exp = "#FF9800" if es_futura else "#111111"    # Naranja si futura
        
        # Mostrar período de validez con colores condicionales
        periodo_frame = tk.Frame(fila_container, bg=fila_container["bg"])
        periodo_frame.grid(row=0, column=3, padx=10, pady=5, sticky="w")
        
        # Etiqueta para fecha de expedición
        exp_label = ctk.CTkLabel(
            periodo_frame, 
            text=fecha_exp_str, 
            font=("Segoe UI", 12),
            text_color=color_exp
        )
        exp_label.pack(side="left")
        
        # Palabra "hasta"
        ctk.CTkLabel(
            periodo_frame, 
            text=" hasta ", 
            font=("Segoe UI", 12)
        ).pack(side="left")
        
        # Etiqueta para fecha de caducidad
        cad_label = ctk.CTkLabel(
            periodo_frame, 
            text=fecha_cad_str, 
            font=("Segoe UI", 12),
            text_color=color_cad
        )
        cad_label.pack(side="left")
        
    except Exception as e:
        # Fallback en caso de error
        periodo = "Fechas no disponibles"
        ctk.CTkLabel(fila_container, text=periodo, font=("Segoe UI", 12)).grid(
            row=0, column=3, padx=10, pady=5, sticky="w")
    
    # Mostrar logo o nombre del algoritmo (columna 0)
    if algoritmo in LOGO_IMAGES and LOGO_IMAGES[algoritmo]:
        logo_label = tk.Label(fila_container, image=LOGO_IMAGES[algoritmo], bg=fila_container["bg"])
        logo_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
    else:
        alg_nombre = "SPHINCS+" if algoritmo == "sphincs" else "Dilithium"
        ctk.CTkLabel(fila_container, text=alg_nombre, font=("Segoe UI", 12)).grid(
            row=0, column=0, padx=10, pady=5, sticky="w")
    
    # Título (columna 1)
    ctk.CTkLabel(fila_container, text=clave["titulo"], font=("Segoe UI", 12)).grid(
        row=0, column=1, padx=10, pady=5, sticky="w")
    
    # Clave pública truncada (columna 2)
    clave_publica = clave.get("pk", clave.get("id", ""))
    if isinstance(clave_publica, bytes):
        import binascii
        clave_publica = binascii.hexlify(clave_publica).decode('ascii')
    clave_truncada = clave_publica[:18] + "..." if len(clave_publica) > 18 else clave_publica
    
    pk_label = ctk.CTkLabel(
        fila_container, 
        text=clave_truncada, 
        text_color="#1a73e8", 
        font=("Segoe UI", 12, "underline"),
        cursor="hand2"
    )
    pk_label.grid(row=0, column=2, padx=10, pady=5, sticky="w")
    
    # Evento específico para el enlace de la clave pública
    def on_pk_click(event=None):
        global APP_INSTANCE
        if APP_INSTANCE and hasattr(APP_INSTANCE, 'mostrar_detalles_clave'):
            nombre_algoritmo = "SPHINCS+" if algoritmo == "sphincs" else "Dilithium"
            APP_INSTANCE.mostrar_detalles_clave(
                pk=clave_publica, 
                titulo=clave["titulo"], 
                algoritmo=nombre_algoritmo,
                caducada=es_caducada
            )
        return "break"
    
    # Configura que el evento de clic en la clave pública se ejecute en lugar del evento de la fila
    # Esperar a que se complete Map antes de vincular el evento específico
    def vincular_pk_despues_de_map(event=None):
        pk_label.unbind("<Button-1>")  # Eliminar cualquier enlace anterior
        pk_label.bind("<Button-1>", on_pk_click)  # Aplicar el enlace específico

    fila_container.bind("<Map>", vincular_pk_despues_de_map, add="+")  # Añadir otro evento Map

    return next_row

def create_certificate_row(lista_frame, row_count, certificado):
    """
    Añade una fila con información de certificado al frame scrollable
    
    Args:
        lista_frame: Frame scrollable donde se coloca la fila
        row_count: Número de fila actual
        certificado: Diccionario con datos del certificado
        
    Returns:
        int: Siguiente número de fila
    """
    # Definir tamaños específicos para columnas de certificados
    column_sizes = [400, 180]  # Certificado, Algoritmo
    
    # Crear la fila base
    fila_container, next_row = create_base_row(
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
    if algoritmo in LOGO_IMAGES and LOGO_IMAGES[algoritmo]:
        logo_label = tk.Label(
            fila_container, 
            image=LOGO_IMAGES[algoritmo], 
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

def create_drop_area(parent, text="Pulse el área y seleccione el documento o arrástrelo aquí", callback=None):
    def open_file_dialog(event=None):
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
        from PIL import Image, ImageTk

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
    frame_container = tk.Frame(parent, width=620, height=220, bg="white", highlightthickness=1, highlightbackground="#E0E0E0")
    frame_container.pack(pady=10)
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
