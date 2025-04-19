import tkinter as tk
import customtkinter as ctk
import os
from PIL import Image, ImageTk
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

def create_button(parent, text, command=None):
    """
    Crea un botón moderno con efecto de sombra proyectada
    """
    # Contenedor principal (transparente)
    container = ctk.CTkFrame(parent, fg_color="transparent")
    
    # Botón de sombra (más grande y oscuro)
    shadow = ctk.CTkButton(
        container,
        text="",  # Sin texto
        width=110,
        height=30,
        corner_radius=5,
        fg_color="#777777",  # Color oscuro para la sombra
        hover_color="#777777",  # La sombra no cambia
        border_width=0,
        state="disabled"  # No interactivo
    )
    shadow.grid(row=0, column=0, padx=0, pady=0)
    
    # Botón principal (ligeramente desplazado)
    button = ctk.CTkButton(
        container,
        text=text,
        command=command,
        width=110,
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

def crear_lista_claves(parent):
    """
    Crea una lista para mostrar las claves de entidad disponibles
    """
    global LOGO_IMAGES  # Usar la variable global para las imágenes
    
    from backend.funcEntGen import cargar_claves_entidad, clasificar_claves_por_estado
    
    # Cargar las claves reales
    SK_ENTIDAD_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sk_entidad.json")
    PK_ENTIDAD_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pk_entidad.json")
    claves_disponibles = cargar_claves_entidad(SK_ENTIDAD_PATH, PK_ENTIDAD_PATH)
    claves_ordenadas = clasificar_claves_por_estado(claves_disponibles)

    # Frame contenedor principal
    contenedor_principal = ctk.CTkFrame(
        parent, 
        fg_color="#FFFFFF",
        corner_radius=25,
        border_width=1,
        border_color="#E0E0E0",
        width=620, 
        height=270
    )
    contenedor_principal.pack_propagate(False)  # Mantener tamaño fijo
    
    # Frame para encabezados (no scrollable)
    header_frame = ctk.CTkFrame(contenedor_principal, fg_color="#FFFFFF", corner_radius=0)
    header_frame.pack(fill="x", padx=10, pady=(10, 0))
    
    # Configurar encabezados fijos con anchos consistentes
    encabezados = ["Algoritmo", "Título", "Clave Pública", "Período de Validez"]
    # Configurar cada columna para mantener el mismo ancho que en las filas
    header_frame.grid_columnconfigure(0, minsize=80)   # Algoritmo
    header_frame.grid_columnconfigure(1, minsize=180)  # Título
    header_frame.grid_columnconfigure(2, minsize=130)  # Clave
    header_frame.grid_columnconfigure(3, minsize=190)  # Período

    # Reemplazar esta sección en crear_lista_claves() (aproximadamente línea 101-104)
    for i, encabezado in enumerate(encabezados):
        label = ctk.CTkLabel(
            header_frame, 
            text=encabezado, 
            font=("Segoe UI", 14, "bold"), 
            text_color="#111111",
            anchor="center",  # Centrar el texto dentro del label
            justify="center"  # Justificación del texto para múltiples líneas
        )
        label.grid(row=0, column=i, padx=10, pady=5, sticky="ew")  # 'ew' para expandir horizontalmente
    
    linea_divisora = tk.Frame(contenedor_principal, height=1, bg="#111111")
    linea_divisora.pack(fill="x", padx=15, pady=(2, 0))
    
    # Frame scrollable para los elementos de la lista
    lista_frame = ctk.CTkScrollableFrame(
        contenedor_principal, 
        fg_color="#FFFFFF",
        corner_radius=0,  # Sin bordes redondeados en el interior
        border_width=0,
        width=620, 
        height=220,
        scrollbar_button_color="#DDDDDD",
    )
    lista_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Contador para filas (empieza en 0 porque ya no tenemos encabezados en este frame)
    row_count = 0
    
    # Cargar las imágenes de los logos solo si aún no están cargadas
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
            log_message("entGenApp.log" ,f"Error detallado al cargar logos: {e}")
    
    # Procesar las claves ordenadas
    for algoritmo, clave, es_caducada, es_futura in claves_ordenadas:
        row_count = agregar_fila_clave(lista_frame, row_count, algoritmo, clave, es_caducada, es_futura)
    
    if row_count > 0:
        # Intentar encontrar el último separador y eliminarlo
        for widget in lista_frame.winfo_children():
            if isinstance(widget, tk.Frame) and widget.winfo_height() == 1:
                if int(widget.grid_info()["row"]) == row_count-1:
                    widget.destroy()
                    break

    # Si no hay claves, mostrar mensaje
    if row_count == 1:
        mensaje = ctk.CTkLabel(
            lista_frame, 
            text="No hay claves disponibles. Genera una nueva clave con el botón superior.", 
            font=("Segoe UI", 12, "italic"),
            text_color="#757575"
        )
        mensaje.grid(row=1, column=0, columnspan=4, padx=20, pady=30)
    
    return contenedor_principal

def agregar_fila_clave(lista_frame, row_count, algoritmo, clave, es_caducada=False, es_futura=False):
    """
    Añade una fila con información de clave al frame scrollable
    """
    # Crear un frame contenedor para toda la fila (para hacerla clicable)
    fila_container = tk.Frame(lista_frame, bg="#FFFFFF")
    fila_container.grid(row=row_count, column=0, columnspan=4, sticky="ew", padx=5, pady=2)

    # Configurar el grid de la fila con anchos fijos para las columnas
    fila_container.grid_columnconfigure(0, minsize=80)    # Algoritmo
    fila_container.grid_columnconfigure(1, minsize=175)   # Título
    fila_container.grid_columnconfigure(2, minsize=135)   # Clave Pública
    fila_container.grid_columnconfigure(3, minsize=190)   # Período
    
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
        
        # Crear el string de período con formato adecuado
        periodo = f"{fecha_exp_str} hasta {fecha_cad_str}"
        
        # Mostrar período de validez con colores condicionales
        periodo_frame = tk.Frame(fila_container, bg="#FFFFFF")
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
        logo_label = tk.Label(fila_container, image=LOGO_IMAGES[algoritmo], bg="#FFFFFF")
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
    clave_truncada = clave_publica[:20] + "..." if len(clave_publica) > 20 else clave_publica
    
    pk_label = ctk.CTkLabel(
        fila_container, 
        text=clave_truncada, 
        text_color="#1a73e8", 
        font=("Segoe UI", 12, "underline"),
        cursor="hand2"  # Siempre mostrar cursor de mano para el PK
    )
    pk_label.grid(row=0, column=2, padx=10, pady=5, sticky="w")
    
    # Evento específico para el enlace de la clave pública
    def on_pk_click(event=None):
        global APP_INSTANCE
        if APP_INSTANCE and hasattr(APP_INSTANCE, 'mostrar_detalles_clave'):
            # Determinar nombre del algoritmo para mostrar correctamente
            nombre_algoritmo = "SPHINCS+" if algoritmo == "sphincs" else "Dilithium"
            APP_INSTANCE.mostrar_detalles_clave(
                pk=clave_publica, 
                titulo=clave["titulo"], 
                algoritmo=nombre_algoritmo,
                caducada=es_caducada
            )
        return "break"  # Detener la propagación del evento
    
    # Vincular el evento específico para el pk_label
    pk_label.bind("<Button-1>", on_pk_click)
    
    # MODIFICACIÓN: Solo hacer clicable el resto si no está caducada
    if not es_caducada:
        # Establecer cursor de mano para indicar que es clicable
        fila_container.configure(cursor="hand2")
        
        # Añadir evento de clic para el resto de la fila
        def on_click(event=None):
            global APP_INSTANCE
            if APP_INSTANCE and hasattr(APP_INSTANCE, 'generar_clave_UI'):
                APP_INSTANCE.generar_clave_UI()
            else:
                log_message("entGenApp.log", "No hay instancia de aplicación configurada")
        
        # Vincular el evento de clic al contenedor
        fila_container.bind("<Button-1>", on_click)
        
        # Vincular el evento a todos los hijos EXCEPTO pk_label
        for child in fila_container.winfo_children():
            if child is not pk_label:  # No vincular al pk_label
                child.bind("<Button-1>", on_click)
    else:
        # Para claves caducadas, cambiar aspecto visual pero mantener pk_label interactivo
        fila_container.configure(bg="#F5F5F5", cursor="X_cursor")
        
        # Configurar correctamente cada tipo de widget
        for widget in fila_container.winfo_children():
            try:
                if isinstance(widget, ctk.CTkLabel):
                    widget.configure(fg_color="#F5F5F5")
                elif isinstance(widget, ctk.CTkFrame):
                    widget.configure(fg_color="#F5F5F5")
                elif isinstance(widget, tk.Frame) or isinstance(widget, tk.Label):
                    widget.configure(bg="#F5F5F5")
            except Exception as e:
                # Ignorar errores de configuración
                pass
                
        # Manejo especial para el frame de periodo
        for widget in fila_container.winfo_children():
            if isinstance(widget, tk.Frame):  # Si es el frame de periodo
                try:
                    widget.configure(bg="#F5F5F5")
                except Exception:
                    pass
                    
                # Procesar cada hijo del frame de periodo por separado
                for child in widget.winfo_children():
                    try:
                        if isinstance(child, ctk.CTkLabel):
                            child.configure(fg_color="#F5F5F5")
                        elif isinstance(child, tk.Label):
                            child.configure(bg="#F5F5F5")
                    except Exception:
                        pass
                
        # Cambiar el cursor para indicar que no es clicable
        fila_container.configure(cursor="X_cursor")
        
    # Añadir línea divisoria después de cada elemento
    linea_divisora = tk.Frame(lista_frame, height=1, bg="#DDDDDD")
    linea_divisora.grid(row=row_count+1, column=0, columnspan=4, sticky="ew", padx=25, pady=2)
    
    return row_count + 2  # +2 para la fila de datos y la línea divisoria