import tkinter as tk
import customtkinter as ctk # type: ignore
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

    def mostrar_mensaje_vacio(lista_frame, mensaje):
        """Muestra un mensaje cuando la lista está vacía"""
        mensaje_label = ctk.CTkLabel(
            lista_frame, 
            text=mensaje, 
            font=("Segoe UI", 12, "italic"),
            text_color="#757575"
        )
        mensaje_label.grid(row=0, column=0, columnspan=4, padx=20, pady=30)

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
    from PIL import Image, ImageTk # type: ignore
    import os

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
    
    return fila_container, row_count + 2, LOGO_IMAGES  # +2 para la fila y la línea