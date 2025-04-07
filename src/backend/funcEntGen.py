import datetime
import hashlib
import json
import os
import secrets
import base64
from Crypto.Cipher import AES
from dilithium_py.ml_dsa import ML_DSA_65
from package.sphincs import Sphincs


from backend.funcComunes import log_message, calcular_hash_firma, calcular_hash_huella


def encrypt_private_key(secret_key, password):
    """Cifra la clave privada con AES-256 en modo CBC usando una contraseña."""
    try:
        # Generar un salt aleatorio de 16 bytes
        salt = secrets.token_bytes(16)

        # Generar un hash de la contraseña con el salt para usarlo como clave AES (256 bits)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

        # Añadir padding con los últimos 50 bits duplicados
        padding = secret_key[-7:]  # 50 bits (aprox. 7 bytes)
        secret_key_padded = secret_key + padding

        # Generar un IV aleatorio de 16 bytes
        iv = secrets.token_bytes(16)

        # Crear el cifrador AES en modo CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Asegurar que el texto a cifrar es múltiplo de 16 bytes (padding PKCS7)
        pad_length = 16 - (len(secret_key_padded) % 16)
        secret_key_padded += bytes([pad_length] * pad_length)

        # Cifrar la clave privada
        encrypted_data = cipher.encrypt(secret_key_padded)

        # Guardar SALT + IV + datos cifrados en Base64 para facilitar almacenamiento
        return base64.b64encode(salt + iv + encrypted_data).decode()

    except Exception as e:
        raise ValueError(f"Error al cifrar clave privada: {e}")

def validate_password(password):
    """Valida que la contraseña cumpla con los requisitos mínimos de seguridad."""
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."
    
    if not any(c.isupper() for c in password):
        return False, "La contraseña debe contener al menos una letra mayúscula."
    
    if not any(c.isdigit() for c in password):
        return False, "La contraseña debe contener al menos un número."
    
    if not any(c in '!@#$%^&*()_-+=[]{}|:;<>,.?/~`' for c in password):
        return False, "La contraseña debe contener al menos un carácter especial."
    
    return True, "Contraseña válida"

def validate_date(date_str):
    """Valida una fecha en formato DD/MM/AAAA y la convierte a formato ISO."""
    try:
        day, month, year = map(int, date_str.split('/'))
        date_obj = datetime.date(year, month, day)
        return date_obj.isoformat()
    except (ValueError, TypeError):
        return None
    
def verificar_campos_generacion_claves(titulo, fecha_ini_str, fecha_cad_str):
    """
    Verifica que los campos para generar una nueva clave sean válidos.
    
    Args:
        titulo (str): Nombre o título de la entidad
        fecha_ini_str (str): Fecha de inicio en formato DD/MM/AAAA
        fecha_cad_str (str): Fecha de caducidad en formato DD/MM/AAAA
        
    Returns:
        tuple: Mensaje de error o éxito, fecha de expedición y fecha de caducidad
    """
    # Validar título
    if not titulo or not titulo.strip():
        return "Debe especificar un nombre para la entidad", None, None

    # Validar fechas
    fecha_expedicion = validate_date(fecha_ini_str)
    if not fecha_expedicion:
        return "Fecha de inicio inválida. Use formato DD/MM/AAAA", None, None
        
    fecha_caducidad = validate_date(fecha_cad_str)
    if not fecha_caducidad:
        return "Fecha de caducidad inválida. Use formato DD/MM/AAAA", None, None
        
    # Verificar que la fecha de caducidad sea posterior a la de expedición
    if fecha_caducidad <= fecha_expedicion:
        return "La fecha de caducidad debe ser posterior a la fecha de inicio", None, None
    
    # Si todo está correcto, devolver datos validados
    return "Datos válidos", fecha_expedicion, fecha_caducidad
    

def cargar_json(ruta_archivo):      
    """Carga un archivo JSON o crea uno nuevo y devuelve lista vacía."""
    if not os.path.exists(ruta_archivo):
        try:
            with open(ruta_archivo, "w") as file:
                json.dump([], file)
            log_message("entGenApp.log", f"Creando archivo JSON en {ruta_archivo}")
        except Exception as e:
            log_message("entGenApp.log", f"ERROR: No se pudo crear {ruta_archivo}: {e}")
        return []
    
    try:
        with open(ruta_archivo, "r") as file:
            return json.load(file)
    except json.JSONDecodeError:
        return []

def validar_y_convertir_clave(hex_clave):
    """
    Valida que una clave en formato hexadecimal sea válida y la convierte a bytes.
    
    Args:
        hex_clave (str): Clave en formato hexadecimal
        tipo_clave (str): "privada" o "pública" para mensajes específicos
        
    Returns:
        bytes: Clave convertida a bytes o None si hay error
    """
    try:
        # Verificar si la clave está vacía
        if not hex_clave:
            log_message("entGenApp.log", f"  ERROR: Clave vacía")
            return None
        
        log_message("entGenApp.log", f"hex: {hex_clave[:50]}... ({len(hex_clave)} caracteres)")
        
        # Validar que solo contiene caracteres hexadecimales válidos
        if not all(c in "0123456789abcdefABCDEF" for c in hex_clave):
            log_message("entGenApp.log", f"  ERROR: Clave contiene caracteres no hexadecimales")
            invalid_chars = [c for c in hex_clave if c not in "0123456789abcdefABCDEF"]
            log_message("entGenApp.log", f"  Caracteres inválidos: {invalid_chars[:20]}...")
            return None
        
        return bytes.fromhex(hex_clave)
        
    except ValueError as e:
        log_message("entGenApp.log", f"  ERROR al convertir clave a bytes: {e}")
        return None

def cargar_claves_entidad(sk_entidad_path, pk_entidad_path):
        """Carga las claves de entidad desde archivos JSON y las procesa."""
        try:
            sk_data= cargar_json(sk_entidad_path)
            pk_data = cargar_json(pk_entidad_path)
            
            # Inicializar diccionario de claves procesadas
            claves_procesadas = {
                "sphincs": [],
                "dilithium": []
            }
            
            # Procesar cada clave individualmente con manejo de errores detallado
            for idx, sk_entry in enumerate(sk_data):
                try:
                    # Extraer información básica
                    algoritmo = sk_entry.get("algoritmo", "").lower()
                    titulo = sk_entry.get("titulo", "Sin título")
                    clave_id = sk_entry.get("id", "")
                    
                    if algoritmo not in ["sphincs", "dilithium"]:
                        log_message("entGenApp.log",f"Saltando clave #{idx+1} con algoritmo desconocido: {algoritmo}")
                        continue
                    
                    log_message("entGenApp.log",f"\nProcesando clave #{idx+1}: {titulo} ({algoritmo})")
                    
                    # Buscar clave pública correspondiente
                    pk_entry = None
                    for pk in pk_data:
                        if pk.get("id") == clave_id:
                            pk_entry = pk
                            break
                    
                    if pk_entry is None:
                        log_message("entGenApp.log",f"  ERROR: No se encontró clave pública para {titulo} (ID: {clave_id})")
                        continue
                    try:
                        # Convertir claves a bytes con verificación detallada
                        log_message("entGenApp.log",f"Validando clave privada de {titulo}...")
                        sk_bytes = validar_y_convertir_clave(sk_entry.get("clave", ""))
                        if sk_bytes is None:
                            continue
                        
                        log_message("entGenApp.log",f"Validando clave pública de {titulo}...")
                        pk_bytes = validar_y_convertir_clave(pk_entry.get("clave", ""))
                        if pk_bytes is None:
                            continue
                        
                    except ValueError as e:
                        log_message("entGenApp.log",f"  ERROR al convertir clave a bytes: {e}")
                        continue
                        
                    # Verificar fechas
                    try:
                        fecha_exp = sk_entry.get("fecha_expedicion", "")
                        fecha_cad = sk_entry.get("fecha_caducidad", "")
                        fecha_actual = datetime.date.today().isoformat()
                        vigente = fecha_cad >= fecha_actual
                        
                        log_message("entGenApp.log",f"  Fechas: {fecha_exp} - {fecha_cad} (Vigente: {vigente})")
                    except Exception as e:
                        log_message("entGenApp.log",f"  ERROR procesando fechas: {e}")
                        vigente = False
                    
                    # Añadir a diccionario de claves procesadas
                    claves_procesadas[algoritmo].append({
                        "id": clave_id,
                        "titulo": titulo,
                        "algoritmo": algoritmo,
                        "fecha_expedicion": fecha_exp,
                        "fecha_caducidad": fecha_cad,
                        "vigente": vigente,
                        "sk": sk_bytes,
                        "pk": pk_bytes
                    })
                    
                    log_message("entGenApp.log",f"  ✓ Clave {algoritmo} añadida correctamente")
                    
                except Exception as e:
                    log_message("entGenApp.log",f"  ERROR general procesando clave #{idx+1}: {e}")
            
            # Resumen final
            log_message("entGenApp.log","\n--- RESUMEN DE CLAVES PROCESADAS ---")
            log_message("entGenApp.log",f"SPHINCS: {len(claves_procesadas['sphincs'])} claves procesadas")
            log_message("entGenApp.log",f"Dilithium: {len(claves_procesadas['dilithium'])} claves procesadas")
            
            return claves_procesadas
            
        except Exception as e:
            log_message("entGenApp.log",f"ERROR CRÍTICO: {e}")
            return None
        
def generar_claves_entidad_backend(titulo, algoritmo, fecha_expedicion, fecha_caducidad, sk_path, pk_path):
    """
    Genera un nuevo par de claves de entidad y las guarda en los archivos correspondientes.
    
    Args:
        titulo (str): Nombre de la entidad
        algoritmo (str): 'sphincs' o 'dilithium'
        fecha_expedicion (str): Fecha de expedición en formato ISO
        fecha_caducidad (str): Fecha de caducidad en formato ISO
        sk_path (str): Ruta al archivo de claves privadas
        pk_path (str): Ruta al archivo de claves públicas
        sphincs_instance: Instancia de Sphincs para generar claves (opcional)
        
    Returns:
        key_id (str) : ID de la clave generada
    """
    try:
        # Generar ID único para esta clave
        import uuid
        key_id = str(uuid.uuid4())
        
        # Generar las claves según el algoritmo seleccionado
        if algoritmo == "sphincs":
            sphincs_inst = Sphincs()
            sk, pk = sphincs_inst.generate_key_pair()
        else:  # dilithium
            pk, sk = ML_DSA_65.keygen()
        
        clave_base = {
            "id": key_id,
            "titulo": titulo,
            "algoritmo": algoritmo,
            "fecha_expedicion": fecha_expedicion,
            "fecha_caducidad": fecha_caducidad
        }
        
        # Crear estructuras específicas añadiendo la clave correspondiente
        nueva_sk = clave_base.copy()
        nueva_sk["clave"] = sk.hex()
        
        nueva_pk = clave_base.copy()
        nueva_pk["clave"] = pk.hex()

        # Leer claves existentes o crear estructura inicial
        claves_sk = cargar_json(sk_path)
        claves_pk = cargar_json(pk_path)
        
        # Añadir nuevas claves
        claves_sk.append(nueva_sk)
        claves_pk.append(nueva_pk)
        
        # Guardar en archivos
        with open(sk_path, "w") as file:
            json.dump(claves_sk, file, indent=4)
        
        with open(pk_path, "w") as file:
            json.dump(claves_pk, file, indent=4)
            
        log_message("entGenApp.log", f"Clave generada y guardada: {titulo} ({algoritmo})")
        return key_id

        
    except Exception as e:
        log_message("entGenApp.log", f"Error al generar claves: {e}")
        return -1