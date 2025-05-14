import tkinter as tk
import customtkinter as ctk # type: ignore
from backend.funcComunes import log_message

ctk.set_appearance_mode("light")

APP_INSTANCE = None  # Para guardar la referencia a la aplicación principal

# Función para establecer la instancia de la aplicación
def set_app_instance_entidad(app):
    global APP_INSTANCE
    APP_INSTANCE = app
    log_message("entGenApp.log", f"APP_INSTANCE establecido: {APP_INSTANCE}")

def create_dropdown(parent, opciones = [], placeholder = ""):
    container = ctk.CTkFrame(parent, fg_color="transparent")
    container.pack(anchor="w", padx=(10, 0)) 
    
    # Frame con bordes para simular bordes del dropdown
    border_frame = ctk.CTkFrame(
        container,
        width=304,
        height=38,
        corner_radius=10,
        fg_color="transparent",
        border_width=1,
        border_color="#E0E0E0"
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

def create_dropdown_with_text(parent, text, opciones = [], placeholder = ""):
    contenedor = ctk.CTkFrame(parent, fg_color="transparent")
    contenedor.pack(anchor="w", pady=(10, 10))  # Alineado a la izquierda

    label = ctk.CTkLabel(contenedor, text=text, font=("Inter", 17), text_color="#111111")
    label.pack(anchor="w")

    entrada = create_dropdown(contenedor, opciones, placeholder)

    return entrada

def create_key_list(parent):
    # Cargar datos de claves
    from backend.funcEntGen import cargar_claves_entidad, clasificar_claves_por_estado
    from frontend.compComunes import create_base_list
    import os

    SK_ENTIDAD_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sk_entidad.json")
    PK_ENTIDAD_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pk_entidad.json")
    claves_disponibles = cargar_claves_entidad(SK_ENTIDAD_PATH, PK_ENTIDAD_PATH)
    claves_ordenadas = clasificar_claves_por_estado(claves_disponibles)
    
    # Definir función para procesar datos
    def procesar_claves(lista_frame, datos):
        row_count = 0
        for algoritmo, clave, es_caducada, es_futura in datos:
            row_count = create_key_row(lista_frame, row_count, clave, es_caducada, es_futura, pk_callback_volver_a= lambda: APP_INSTANCE.vista_inicial_entidad_generadora())
        return row_count
    
    # Definir encabezados específicos para claves
    encabezados = ["Algoritmo", "Título", "Clave Pública", "Período de Validez"]
    column_sizes = [80, 180, 120, 220]  # Tamaños por columna

    # Obtener la estructura base de la lista
    contenedor_principal = create_base_list(
        parent, 
        height=300,
        empty_message="No hay claves disponibles. Genera una nueva clave con el botón superior.",
        process_data_function=procesar_claves,
        data=claves_ordenadas,
        headers=encabezados,
        column_sizes=column_sizes,
        max_visible_items=4
    )
        
    return contenedor_principal

def create_key_row(lista_frame, row_count, clave, es_caducada=False, es_futura=False, es_clicable=True, separador=True, pk_callback_volver_a = None ):
    """
    Añade una fila con información de clave al frame scrollable
    """

    algoritmo = clave.get("algoritmo")
    log_message("entGenApp.log", f"Creando fila para clave: {clave.get('titulo')} ({algoritmo})")
    from frontend.compComunes import create_base_row
    # Definir tamaños específicos para columnas de claves
    column_sizes = [80, 175, 150, 190]  # Algoritmo, Título, PK, Período

    # Crear la fila base
    fila_container, next_row = create_base_row(
        lista_frame=lista_frame,
        row_count=row_count,
        column_sizes=column_sizes,
        click_callback=(lambda event=None: APP_INSTANCE.vista_crear_certificado(clave)) if es_clicable else None,
        is_disabled=es_caducada,
        separator=separador
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
    if algoritmo in ["sphincs", "dilithium"]:
        from frontend.compComunes import resize_image_proportionally
        alg_nombre = algoritmo.capitalize()  # Capitalize first letter for image name
        logo_img = resize_image_proportionally(alg_nombre, desired_height=40)
        logo_label = ctk.CTkLabel(fila_container, image=logo_img, text="", fg_color=fila_container["bg"])
        logo_label.grid(row=0, column=0, padx= 0 if algoritmo == "dilithium" else (5,0), pady=5, sticky="w")
    else:
        alg_nombre = "SPHINCS+" if algoritmo == "sphincs" else "Dilithium"
        ctk.CTkLabel(fila_container, text=alg_nombre, font=("Segoe UI", 12)).grid(
            row=0, column=0, padx=(10,0), pady=5, sticky="w")
    
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
        from backend.funcComunes import format_iso_display
        from frontend.compComunes import vista_mostrar_pk
        log_message("entGenApp.log", f"Clic en clave pública detectado. APP_INSTANCE={APP_INSTANCE}")
        
        if APP_INSTANCE:
            log_message("entGenApp.log", f"APP_INSTANCE tiene atributo vista_mostrar_pk: {hasattr(APP_INSTANCE, 'vista_mostrar_pk')}")
        else:
            log_message("entGenApp.log", "APP_INSTANCE es None")

        nombre_algoritmo = "SPHINCS+" if algoritmo == "sphincs" else "Dilithium"
        log_message("entGenApp.log", f"Llamando a vista_mostrar_pk con título={clave['titulo']}, algoritmo={nombre_algoritmo}")
        vista_mostrar_pk(
            parent=APP_INSTANCE.root,
            volver_a= pk_callback_volver_a,
            pk=clave_publica, 
            titulo=clave["titulo"], 
            algoritmo=algoritmo,
            fecha=f"{format_iso_display(clave['fecha_expedicion'])} hasta {format_iso_display(clave['fecha_caducidad'])}",
        )
        return "break"
    
    # Configura que el evento de clic en la clave pública se ejecute en lugar del evento de la fila
    def vincular_pk_despues_de_map(event=None):
        log_message("entGenApp.log", f"Vinculando evento de clic a pk_label")

        pk_label.unbind("<Button-1>")  # Eliminar cualquier enlace anterior
        pk_label.bind("<Button-1>", on_pk_click)  # Aplicar el enlace específico
        # También verifica si fila_container tiene el atributo special_widgets
        if hasattr(fila_container, 'special_widgets'):
            fila_container.special_widgets.append(pk_label)
            log_message("entGenApp.log", f"pk_label añadido a special_widgets")
        else:
            log_message("entGenApp.log", f"fila_container no tiene atributo special_widgets")        
    fila_container.bind("<Map>", vincular_pk_despues_de_map, add="+")  # Añadir otro evento Map

    return next_row