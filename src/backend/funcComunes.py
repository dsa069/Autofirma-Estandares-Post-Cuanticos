def init_paths():
    """
    Inicializa las rutas base y configura el path de Python.
    
    Returns:
        str: La ruta base de la aplicación (BASE_DIR)
    """
    import sys
    import os
    if getattr(sys, 'frozen', False):
        BASE_DIR = sys._MEIPASS  # Carpeta temporal de PyInstaller
    else:
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # src/

    # Añadir la carpeta padre (donde está 'package') a sys.path
    parent_dir = os.path.dirname(BASE_DIR)  # Subir un nivel desde 'src'
    sys.path.insert(0, parent_dir)
    
    return BASE_DIR

def log_message(log_file_name, message):
    """
    Registra un mensaje en un archivo de log en la carpeta 'logs'.
    
    Args:
        log_file_name (str): Nombre del archivo de log (ejemplo: "firmaApp.log")
        message (str): Mensaje a registrar
    
    Returns:
        bool: True si el mensaje se registró correctamente, False en caso contrario
    """
    try:
        import os
        # Obtener el directorio raíz del proyecto (src)
        current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Crear la carpeta de logs
        logs_folder = os.path.join(current_dir, "logs")
        if not os.path.exists(logs_folder):
            os.makedirs(logs_folder)
        
        log_file_path = os.path.join(logs_folder, log_file_name)

        import datetime
        # Fecha y hora actual
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Crear la entrada de log
        log_entry = f"[{timestamp}] {message}\n"
        
        # Escribir en el archivo de log (modo append)
        with open(log_file_path, "a", encoding="utf-8") as log_file:
            log_file.write(log_entry)
            
        return True
        
    except Exception as e:
        print(f"Error al registrar en el log: {e}")
        return False
    
def calcular_hash_firma(cert):
    """ordered_keys de la lo que firma la entidad en el certificado."""
    ordered_keys_firma = [
        "nombre",
        "dni",
        "fecha_expedicion",
        "fecha_caducidad",
        "user_public_key",
        "entity_public_key",
        "algoritmo"
    ]
    return calcular_hash_ordenado(cert, ordered_keys_firma).digest()

def calcular_hash_huella(cert):
    """ordered_keys de la huella digital del certificado."""
    ordered_keys = [
        "nombre",
        "dni",
        "fecha_expedicion",
        "fecha_caducidad",
        "user_public_key",
        "entity_public_key",
        "algoritmo",
        "firma",
        "user_secret_key"
    ]
    return calcular_hash_ordenado(cert, ordered_keys).hexdigest()    
    
def calcular_hash_ordenado(data, ordered_keys):
    """Calcula el hash SHA-256 de los datos serializados asegurando el mismo orden."""
    import json
    import hashlib

    ordered_data = {key: data[key] for key in ordered_keys if key in data}
    serialized_data = json.dumps(ordered_data, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized_data.encode())

def firmar_hash(hash_data, clave_privada, algoritmo):
    from package.sphincs import Sphincs

    # Firmar según el algoritmo seleccionado
    if algoritmo.lower() == "sphincs":
        sphincs = Sphincs()
        firma = sphincs.sign(hash_data, clave_privada)
    elif algoritmo.lower() == "dilithium":
        from dilithium_py.ml_dsa import ML_DSA_65 # type: ignore
        firma = ML_DSA_65.sign(clave_privada, hash_data)
    else:
        return None
    return firma

