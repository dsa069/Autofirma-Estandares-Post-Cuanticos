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
    log_message("entGenApp.log", f"APP_INSTANCE establecido: {APP_INSTANCE}")

ctk.set_appearance_mode("light")

def center_window(root):
    """Centra la ventana en la pantalla"""
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')

def setup_app_icons(root, base_dir, icon_name):
    import ctypes
    import os
    import sys
    from tkinter import messagebox, PhotoImage
    if getattr(sys, 'frozen', False):
        # Ejecutando como archivo compilado
        ruta_icono = os.path.join(base_dir, f"{icon_name}.ico")
        ruta_icono_png = os.path.join(base_dir, f"{icon_name}.png")
    else:
        # Ejecutando como script Python
        ruta_icono = os.path.join(base_dir, "img", f"{icon_name}.ico")
        ruta_icono_png = os.path.join(base_dir, "img", f"{icon_name}.png")
    # Asegurar que Windows asocia la aplicación correctamente a la barra de tareas
    myappid = 'miapp.certificadosdigitales'  # Nombre único
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

    # (TRUCO) Crear ventana oculta para forzar el icono en la barra de tareas
    root.ventana_oculta = tk.Toplevel()
    root.ventana_oculta.withdraw()  # Oculta la ventana

    # Intentar establecer el icono .ico
    if os.path.exists(ruta_icono):
        root.iconbitmap(ruta_icono)  # Icono en la cabecera
        root.ventana_oculta.iconbitmap(ruta_icono)  # Forzar icono en barra de tareas
    else:
        messagebox.showwarning("Advertencia", "⚠️ Icono .ico no encontrado, verifica la ruta.")

    # Intentar establecer el icono .png en la barra de tareas
    if os.path.exists(ruta_icono_png):
        icono = PhotoImage(file=ruta_icono_png)
        root.iconphoto(True, icono)  # Icono en la barra de tareas
    else:
        messagebox.showwarning("Advertencia", "⚠️ Icono .png no encontrado, verifica la ruta.")

def vista_mostrar_pk(parent, base_dir, volver_a, pk, titulo, algoritmo, fecha):
    """
    Muestra los detalles de la clave seleccionada en la interfaz principal
    """
    vista = crear_vista_nueva(parent)

    # Contenedor horizontal: imagen + info PDF
    cabecera_certificado = tk.Frame(vista, bg="#F5F5F5")
    cabecera_certificado.pack(fill="x", padx=(40, 0), pady=(40, 30))

    algoritmo_img = resize_image_proportionally(base_dir, algoritmo, desired_height=75)

    image_label = tk.Label(cabecera_certificado, image=algoritmo_img, bg="#F5F5F5")
    image_label.image = algoritmo_img
    image_label.pack(side="left", padx=(0, 30))

    # Título y ruta
    cd_padding = (25, 0) if algoritmo == "sphincs" else (5, 0)
    certificate_frame = tk.Frame(cabecera_certificado, bg="#F5F5F5")
    certificate_frame.pack(side="left", fill="x", expand=True, pady=cd_padding)

    label_title = tk.Label(
        certificate_frame,
        text=titulo,
        fg="#111111",
        bg="#F5F5F5",
        font=("Inter", 18),
        anchor="w"
    )
    label_title.pack(anchor="w")

    label_fecha = tk.Label(
        certificate_frame,
        text=fecha,
        fg="#333333",
        bg="#F5F5F5",
        font=("Inter", 13),
        anchor="w"
    )
    label_fecha.pack(anchor="w")
    
    label_pk = tk.Label(
        vista,
        text="Clave Pública:",
        fg="#111111",
        font=("Inter", 14),
        bg="#F5F5F5",
        anchor="w",
        justify="left"
    )
    label_pk.pack(anchor="w", padx=37)

    # Do this instead:
    pk_list_container = create_pk_list(vista, pk)
    pk_list_container.pack(padx=10, pady=10) 

    volver_btn = create_button(vista, "Volver", volver_a)
    volver_btn.pack(pady=10)

    return vista

def crear_vista_nueva(parent):
    """
    Limpia la interfaz actual y crea un nuevo frame principal
    """
    # Limpiar la interfaz actual - manejar diferentes tipos de widgets
    for widget in parent.winfo_children():
        try:
            widget.pack_forget()
        except:
            pass  # Ignorar errores para widgets que no usan pack
    
    # Crear y configurar el frame principal
    frame = ctk.CTkFrame(
        parent, 
        fg_color="#F5F5F5"
    )
    frame.pack(fill="both", expand=True)
    
    return frame

def create_text(parent, text, wraplength=600, font_size=16):
    """
    Crea un texto con estilo moderno.
    """
    label = ctk.CTkLabel(
        parent,
        text=text,
        font=("Inter", font_size),
        text_color="#111111",
        wraplength=wraplength,
        anchor="w",
        justify="left"
    )

    label.pack(anchor="w")

    return label
    

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
        height=37,
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
        height=35,
        corner_radius=5,
        border_width=1,
        border_color="#999999",
        fg_color="#DCDCDC",
        text_color="#111111",
        hover_color="#BBBBBB",
        font=("Inter", 16),
    )
    # Posicionar con offset para crear efecto de sombra
    button.grid(row=0, column=0, padx=(0, 5), pady=(0, 6))
    
    # Asegurar que el botón esté por encima de la sombra
    button.lift()
    
    return container

def create_text_field_with_title(parent, text, placeholder="", width=450, password=False):
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

def resize_image_proportionally(base_dir, algoritmo, desired_height=75):
    """
    Carga una imagen desde una ruta y la redimensiona manteniendo las proporciones.
    """
    from PIL import Image, ImageTk # type: ignore
    import os
    # En lugar de usar algoritmo_img, carga directamente desde el archivo
    img_path = os.path.join(base_dir, "img")        
    if algoritmo == "sphincs":
        image_path = os.path.join(img_path, "Sphincs.png")
    else:  # dilithium
        image_path = os.path.join(img_path, "Dilithium.png")
    
    # Cargar imagen original
    original_img = Image.open(image_path)

    # Obtener dimensiones originales
    original_width, original_height = original_img.size

    # Calcular ancho proporcionalmente
    aspect_ratio = original_width / original_height
    desired_width = int(desired_height * aspect_ratio)

    # Redimensionar manteniendo las proporciones
    original_img = original_img.resize((desired_width, desired_height), Image.LANCZOS)
    
    # Convertir a formato para Tkinter
    return ImageTk.PhotoImage(original_img)

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

def create_pk_list(parent, pk):
    # Cargar datos de claves
    from frontend.compComunes import create_base_list
    
    # Definir función para procesar datos
    def procesar_claves(lista_frame, datos):
        row_count = create_pk_row(lista_frame, 0, pk)
        return row_count

    max_items = 0 if len(pk) > 200 else 1

    # Obtener la estructura base de la lista
    contenedor_principal = create_base_list(
        parent, 
        height=300,
        empty_message="Error al mostrar la clave",
        process_data_function=procesar_claves,
        data=[pk],
        max_visible_items=max_items
    )
        
    return contenedor_principal

def create_base_row(lista_frame, row_count, column_sizes = [600], click_callback=None, is_disabled=False):
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
    radio_esquinas = 0 if is_disabled else 25
    column_count = len(column_sizes)

    # Contenedor de la fila
    fila_container = ctk.CTkFrame(lista_frame, fg_color=color_fondo, corner_radius=radio_esquinas)
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

def create_pk_row(lista_frame, row_count, clave):
    """
    Añade una fila con información de clave al frame scrollable
    """
    log_message("entGenApp.log", f"Creando fila para clave: {clave})")
    from frontend.compComunes import create_base_row
    
    def callback_copy(event=None, widget=None):
        if APP_INSTANCE and APP_INSTANCE.root:
            # Guardar el color original
            original_bg = fila_container["bg"]
            
            # Cambiar temporalmente el color de fondo
            fila_container.configure(bg="#E3F2FD")  # Azul claro
            
            # Copiar al portapapeles
            copiar_al_portapapeles(APP_INSTANCE.root, clave, lista_frame)
            
            # Restaurar color original después de un tiempo
            APP_INSTANCE.root.after(1500, lambda: fila_container.configure(bg=original_bg))
        return "break"

    # Crear la fila base
    fila_container, next_row, _ = create_base_row(
        lista_frame=lista_frame,
        row_count=row_count,
        click_callback=callback_copy,
    )
    
    pk_label = ctk.CTkLabel(
        fila_container, 
        text=clave, 
        text_color="#333333", 
        font=("Inter", 14),
        wraplength=560,  
        justify="left"
    )
    pk_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

    def copiar_al_portapapeles(window, text, scrollable_frame):
        """Copia texto al portapapeles y muestra confirmación"""
        window.clipboard_clear()
        window.clipboard_append(text)
        
        # Obtener el contenedor principal (padre del scrollable_frame)
        parent_container = scrollable_frame.master.master
        
        # Crear frame para el mensaje si no existe
        if not hasattr(parent_container, 'message_frame'):
            parent_container.message_frame = ctk.CTkFrame(
                parent_container,
                fg_color="#E8F5E9",  # Verde claro
                corner_radius=8,
                height=40
            )
            
            # Encontrar la última fila usada en el contenedor
            last_row = 0
            for child in parent_container.winfo_children():
                grid_info = child.grid_info()
                if grid_info:  # Si el widget está usando grid
                    last_row = max(last_row, int(grid_info.get('row', 0)))
            
            # Usar grid en lugar de pack
            parent_container.message_frame.grid(row=last_row+1, column=0, columnspan=999, 
                                                padx=10, pady=5, sticky="ew")
            parent_container.message_frame.grid_remove()  # Ocultar inicialmente
            
            # Crear el mensaje dentro del frame
            parent_container.message_label = ctk.CTkLabel(
                parent_container.message_frame,
                text="¡Clave copiada al portapapeles!",
                font=("Segoe UI", 12),
                text_color="#4CAF50"
            )
            parent_container.message_label.pack(pady=8)  # Dentro del frame pequeño sí podemos usar pack
        
        # Mostrar el mensaje
        parent_container.message_frame.grid()
        
        # Ocultar después de 2 segundos
        window.after(1500, parent_container.message_frame.grid_remove)

    return next_row

def key_data_list(parent, key_data):
    """
    Crea una lista visual para mostrar datos de un certificado (titular, dni, etc.).
    """
    from frontend.compComunes import create_base_list

    def procesar_key_data(lista_frame, datos):
        row_count = 0
        for titulo, valor in datos:
            row_count = key_data_row(lista_frame, row_count, titulo, valor)
        return row_count

    # Ajuste: si hay muchos datos, permitir más ítems visibles
    max_items = 4 if len(key_data) > 6 else 2

    contenedor_principal = create_base_list(
        parent,
        height=360,
        empty_message="Datos de certificado no disponibles",
        process_data_function=procesar_key_data,
        data=key_data,
        column_sizes=[200, 400],  # Tamaño para título y valor
        max_visible_items=max_items
    )

    return contenedor_principal

def key_data_row(lista_frame, row_count, titulo, valor):
    """
    Crea una fila visual con título y valor para la lista de datos de un certificado.
    """
    from frontend.compComunes import create_base_row

    # Crear la fila base
    fila_container, next_row, _ = create_base_row(
        lista_frame=lista_frame,
        row_count=row_count,
        column_sizes=[200, 400]  # Primera columna para título, segunda para valor
    )

    # Etiqueta de título
    titulo_label = ctk.CTkLabel(
        fila_container,
        text=titulo,
        text_color="#666666",
        font=("Segoe UI", 13, "bold"),
        anchor="w"
    )
    titulo_label.grid(row=0, column=0, padx=10, pady=8, sticky="w")

    # Etiqueta de valor
    valor_label = ctk.CTkLabel(
        fila_container,
        text=valor,
        text_color="#111111",
        font=("Segoe UI", 13),
        anchor="w"
    )
    valor_label.grid(row=0, column=1, padx=10, pady=8, sticky="w")

    return next_row
