import tkinter as tk
import customtkinter as ctk # type: ignore
from backend.funcComunes import log_message

ctk.set_appearance_mode("light")

# Variable global para mantener referencias a las imágenes
APP_INSTANCE = None  # Para guardar la referencia a la aplicación principal
BASE_DIR = None  # Para guardar la ruta base de la aplicación

# Función para establecer la instancia de la aplicación
def set_app_instance(app):
    global APP_INSTANCE
    APP_INSTANCE = app

def set_base_dir(base_dir):
    global BASE_DIR
    BASE_DIR = base_dir

def center_window(root):
    """Centra la ventana en la pantalla"""
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2) - 50
    root.geometry(f'{width}x{height}+{x}+{y}')

def setup_app_icons(root, icon_name):
    """
    Configura el icono de la aplicación en Windows y el icono de la barra de tareas.
    """
    import ctypes
    import os
    import sys
    from tkinter import messagebox, PhotoImage
    if getattr(sys, 'frozen', False):
        # Ejecutando como archivo compilado
        ruta_icono = os.path.join(BASE_DIR, f"{icon_name}.ico")
        ruta_icono_png = os.path.join(BASE_DIR, f"{icon_name}.png")
    else:
        # Ejecutando como script Python
        ruta_icono = os.path.join(BASE_DIR, "img", f"{icon_name}.ico")
        ruta_icono_png = os.path.join(BASE_DIR, "img", f"{icon_name}.png")
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

def resize_image_proportionally(nombre, desired_height=75):
    """
    Carga una imagen desde una ruta y la redimensiona manteniendo las proporciones, devolviendo CTkImage.
    """
    from PIL import Image # type: ignore
    from customtkinter import CTkImage # type: ignore
    import os

    image_path = os.path.join(BASE_DIR, "img", f"{nombre}.png")

    # Cargar imagen original
    original_img = Image.open(image_path)

    # Obtener dimensiones originales
    original_width, original_height = original_img.size

    # Calcular ancho proporcionalmente
    aspect_ratio = original_width / original_height
    desired_width = int(desired_height * aspect_ratio)

    # Redimensionar manteniendo las proporciones
    resized_img = original_img.resize((desired_width, desired_height), Image.LANCZOS)

    # Convertir a CTkImage para usar en CustomTkinter
    return CTkImage(light_image=resized_img, dark_image=resized_img, size=(desired_width, desired_height))

def vista_mostrar_pk(parent, volver_a, pk, titulo, algoritmo, fecha):
    """
    Muestra los detalles de la clave seleccionada en la interfaz principal
    """
    vista = crear_vista_nueva(parent)

    # Contenedor horizontal: imagen + info PDF
    cabecera_certificado = tk.Frame(vista, bg="#F5F5F5")
    cabecera_certificado.pack(fill="x", padx=(40, 0), pady=(40, 30))

    algoritmo_img = resize_image_proportionally(algoritmo.capitalize(), desired_height=75)

    image_label = ctk.CTkLabel(
        cabecera_certificado, 
        image=algoritmo_img,
        text="",
        fg_color="#F5F5F5"
    )
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

def create_text_field_with_title(parent, text, placeholder="", width=450):
    """
    Crea un campo de texto con título
    """
    contenedor = ctk.CTkFrame(parent, fg_color="transparent")
    contenedor.pack(anchor="w", pady=(10, 10))  # Alineado a la izquierda

    label = ctk.CTkLabel(contenedor, text=text, font=("Inter", 17), text_color="#111111")
    label.pack(anchor="w")

    entrada = create_text_field(contenedor, placeholder, width)
    entrada.pack(anchor="w", pady=(5, 0))

    return entrada

def create_text_field(parent, placeholder = "", width=450):
    """
    Crea un campo de texto con estilo moderno.
    """
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

def create_base_list(parent, height=270, empty_message=None, process_data_function=None, data=None, headers=None, column_sizes=None, max_visible_items=1, separator=True, custom_header_function=None):
    """
    Crea un esqueleto básico para cualquier lista con estilo consistente.
    Args:
        parent: Frame padre donde se coloca la lista
        height: Altura del contenedor de la lista
        empty_message: Mensaje a mostrar si la lista está vacía
        process_data_function: Función para procesar los datos y crear filas
        data: Datos a mostrar en la lista
        headers: Encabezados de la lista (opcional)
        column_sizes: Tamaños de las columnas (opcional)
        max_visible_items: Número máximo de elementos visibles antes de mostrar el scrollbar
        separator: Si se debe añadir un separador entre filas
        custom_header_function: Función para crear encabezados personalizados (opcional)
    """

    def setup_list_headers(header_frame, headers, column_sizes):
        """
        Configura los encabezados de la lista y sus tamaños.
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
    
    if custom_header_function:
        header_frame = custom_header_function(contenedor_principal)
        linea_divisora = tk.Frame(contenedor_principal, height=1, bg="#CCCCCC")
        linea_divisora.pack(fill="x", padx=15, pady=(2, 0))
    elif headers and column_sizes:
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
    if row_count > 0 and separator:
        eliminar_ultimo_separador(lista_frame, row_count)
    if row_count < 1 and empty_message:
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

def create_base_row(lista_frame, row_count, column_sizes = [600], click_callback=None, is_disabled=False, separator=True):
    """
    Crea una fila base con estructura consistente para cualquier lista.

    Args:
        lista_frame: Frame scrollable donde se coloca la fila
        row_count: Número de fila actual
        column_sizes: Tamaños de las columnas
        click_callback: Función a ejecutar al hacer clic en la fila
        is_disabled: Si la fila está deshabilitada (sin interactividad)
        separator: Si se debe añadir un separador después de la fila
    
    Returns:
        fila_container: Contenedor de la fila
        next_row: Número de fila siguiente
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
    
    if separator:
        # Añadir línea divisoria después del elemento
        linea_divisora = tk.Frame(lista_frame, height=1, bg="#DDDDDD")
        linea_divisora.grid(row=row_count+1, column=0, columnspan=column_count, 
                        sticky="ew", padx=25, pady=2)
    
    return fila_container, row_count +  (2 if separator else 1)  # +2 para la fila y la línea

def create_pk_list(parent, pk):
    """
    Crea una lista visual para mostrar la clave pública.
    """
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

def create_pk_row(lista_frame, row_count, clave):
    """
    Añade una fila con información de clave al frame scrollable
    """
    log_message("entGenApp.log", f"Creando fila para clave: {clave})")
    from frontend.compComunes import create_base_row
    
    def callback_copy(event=None, widget=None):
        if APP_INSTANCE and APP_INSTANCE.root:
            # Guardar el color original
            original_fg = fila_container.cget("fg_color")
            
            # Cambiar temporalmente el color de fondo
            fila_container.configure(fg_color="#E3F2FD")  # Azul claro
            
            # Copiar al portapapeles
            copiar_al_portapapeles(APP_INSTANCE.root, clave, lista_frame)
            
            # Restaurar color original después de un tiempo
            APP_INSTANCE.root.after(1500, lambda: fila_container.configure(fg_color=original_fg))

        return "break"

    # Crear la fila base
    fila_container, next_row = create_base_row(
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

def cert_data_list(parent, cert_data, fecha_firma=None, cert_valido = 1):
    """
    Crea una lista visual para mostrar datos de un certificado (titular, dni, etc.).
    """
    from frontend.compComunes import create_base_list
    from backend.funcComunes import format_iso_display

    key_data = [
        ("Titular", cert_data.get('nombre')),
        ("DNI", cert_data.get('dni')),
        ("Fecha Expedición", f"{format_iso_display(cert_data.get('fecha_expedicion'))}"),
        ("Fecha Caducidad", f"{format_iso_display(cert_data.get('fecha_caducidad'))}"),
        ("Algoritmo firma", cert_data.get('algoritmo').upper()),
        ("Algoritmo hash firma", "SHA256"),
        ("Entidad certificadora", "SafeInQ"),
        ("Clave Pública Usuario", cert_data.get('user_public_key')[:30] + "...")
    ]

    # Define callback for public key row
    def on_pk_click(event=None):
        from frontend.compComunes import vista_mostrar_pk
        log_message("entGenApp.log", "Clic en clave pública de certificado")
        
        if APP_INSTANCE:
            # Determinar la función de retorno según el origen
            if cert_valido in [0, 2]:  # Viene de vista_resultado_firma
                return_function = lambda: APP_INSTANCE.vista_info_certificado(
                    cert_data, 
                    fecha_firma, 
                    APP_INSTANCE.vista_resultado_firma, 
                    cert_valido
                )
            elif fecha_firma:  # Viene de verify_signatures
                return_function = lambda: APP_INSTANCE.vista_info_certificado(
                    cert_data, 
                    fecha_firma, 
                    APP_INSTANCE.verify_signatures
                )
            else:  # Otro origen
                return_function = lambda: APP_INSTANCE.vista_resultado_certificado(cert_data)
            # Get the full public key and display it in a new view
            vista_mostrar_pk(
                parent=APP_INSTANCE.root,
                volver_a=return_function,
                pk=cert_data.get('user_public_key'), 
                titulo=f"{cert_data.get("nombre")} - {cert_data.get("dni")}",
                algoritmo=cert_data.get('algoritmo').lower(),
                fecha=f"{format_iso_display(cert_data.get('fecha_expedicion'))} hasta {format_iso_display(cert_data.get('fecha_caducidad'))}",
            )
        return "break"

    def procesar_key_data(lista_frame, datos):
        """ 
        Procesa los datos de la clave y crea filas en el frame.
        """
        row_count = 0
        for titulo, valor in datos:
            # Check if this is the public key row
            if titulo == "Clave Pública Usuario":
                row_count = cert_data_row(lista_frame, row_count, titulo, valor, on_pk_click)
            else:
                row_count = cert_data_row(lista_frame, row_count, titulo, valor)
        return row_count

    def custom_header(parent_frame):
        # Frame principal sin width fijo para que se adapte
        header_frame = ctk.CTkFrame(parent_frame, fg_color="transparent", corner_radius=0)
        header_frame.pack(pady=10, padx=20, fill="x")
        
        # Configuración con 3 columnas
        header_frame.grid_columnconfigure(0, weight=0)  # Icono (ancho fijo)
        header_frame.grid_columnconfigure(1, weight=1)  # Nombre (expandible)
        header_frame.grid_columnconfigure(2, weight=0)  # Fecha (ancho fijo)
        
        # 1. ICONO
        algorithm_image = resize_image_proportionally(cert_data.get('algoritmo').capitalize(), 40)
        img_label = ctk.CTkLabel(
            header_frame, 
            image=algorithm_image,
            text="",  # Texto vacío necesario para CTkLabel
            fg_color="transparent"
        )
        img_label.grid(row=0, column=0, padx=(0, 10))
        
        # 2. NOMBRE Y DNI
        text_label = ctk.CTkLabel(
            header_frame, 
            text=f'{cert_data.get("nombre")} - {cert_data.get("dni")}',
            font=("Inter", 17), 
            text_color="#111111",
        )
        text_label.grid(row=0, column=1, sticky="w", pady=(5, 0))
        
        # 3. FECHA (a la derecha)
        if fecha_firma:
            fecha_label = ctk.CTkLabel(
                header_frame, 
                text=f'{format_iso_display(fecha_firma)}',
                font=("Inter", 17), 
                text_color="#555555",
            )
            fecha_label.grid(row=0, column=2, sticky="e", padx=(10, 0))
        
        return header_frame

    contenedor_principal = create_base_list(
        parent,
        height=344,
        empty_message="Datos de certificado no disponibles",
        process_data_function=procesar_key_data,
        data=key_data,
        column_sizes=[200, 400],  # Tamaño para título y valor
        max_visible_items=10,
        separator=False,
        custom_header_function=custom_header
    )

    return contenedor_principal

def cert_data_row(lista_frame, row_count, titulo, valor, callback=None):
    """
    Crea una fila visual con título y valor para la lista de datos de un certificado.
    """
    from frontend.compComunes import create_base_row

    # Crear la fila base
    fila_container, next_row = create_base_row(
        lista_frame=lista_frame,
        row_count=row_count,
        column_sizes=[200, 400] ,
        separator=False,
        click_callback=callback
    )

    # Etiqueta de título
    titulo_label = ctk.CTkLabel(
        fila_container,
        text=titulo,
        text_color="#111111",
        font=("Inter", 16),
        anchor="w"
    )
    titulo_label.grid(row=0, column=0, padx=(30, 0), pady=0, sticky="w")

    # Etiqueta de valor
    valor_label = ctk.CTkLabel(
        fila_container,
        text=valor,
        text_color="#1a73e8" if callback else "#555555",
        font=("Inter", 16, "underline") if callback else ("Inter", 16),
        anchor="center",
        cursor="hand2" if callback else ""
    )
    valor_label.grid(row=0, column=1, pady=0, sticky="ew")

    return next_row
