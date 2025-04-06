import datetime
import hashlib
import json
import os
import secrets
import base64
from Crypto.Cipher import AES
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

def leer_claves_entidad(sk_entidad_path, pk_entidad_path):
        """
        Versión de depuración para identificar el problema con Dilithium
        """
        
        # Verificación de archivos
        sk_exists = os.path.exists(sk_entidad_path)
        pk_exists = os.path.exists(pk_entidad_path)
        
        log_message("entGenApp.log",f"Archivo SK existe: {sk_exists}")
        log_message("entGenApp.log",f"Archivo PK existe: {pk_exists}")
    
        # Si no existen los archivos, crearlos como arrays JSON vacíos
        if not sk_exists:
            log_message("entGenApp.log",f"Creando archivo de claves privadas en {sk_entidad_path}")
            try:
                with open(sk_entidad_path, "w") as file:
                    json.dump([], file)
                sk_exists = True
            except Exception as e:
                error_msg = f"ERROR: No se pudo crear el archivo de claves privadas: {e}"
                log_message("entGenApp.log",error_msg)
                return claves_procesadas
            
        if not pk_exists:
            log_message("entGenApp.log",f"Creando archivo de claves públicas en {pk_entidad_path}")
            try:
                with open(pk_entidad_path, "w") as file:
                    json.dump([], file)
                pk_exists = True
            except Exception as e:
                error_msg = f"ERROR: No se pudo crear el archivo de claves públicas: {e}"
                log_message("entGenApp.log",error_msg)
                return claves_procesadas
    
        try:
            # Cargar archivos como texto primero para verificar JSON válido
            with open(sk_entidad_path, "r") as file:
                sk_text = file.read()
                log_message("entGenApp.log",f"Archivo SK cargado: {len(sk_text)} bytes")
            
            with open(pk_entidad_path, "r") as file:
                pk_text = file.read()
                log_message("entGenApp.log",f"Archivo PK cargado: {len(pk_text)} bytes")

            # Intentar parsear JSON
            try:
                sk_data = json.loads(sk_text)
                log_message("entGenApp.log",f"SK JSON parseado correctamente: {type(sk_data)}, {len(sk_data)} elementos")
            
                # Verificar si hay elementos en el archivo
                if not sk_data:
                    error_msg = "No hay claves privadas en el archivo. Debe generar al menos una clave."
                    log_message("entGenApp.log",error_msg)
                    return claves_procesadas
                
            except json.JSONDecodeError as e:
                log_message("entGenApp.log",f"Error al parsear SK JSON: {e}")
                return None
            
            try:
                pk_data = json.loads(pk_text)
                log_message("entGenApp.log",f"PK JSON parseado correctamente: {type(pk_data)}, {len(pk_data)} elementos")

               # Verificar si hay elementos en el archivo
                if not pk_data:
                    error_msg = "No hay claves públicas en el archivo. Debe generar al menos una clave."
                    log_message("entGenApp.log",error_msg)
                    return claves_procesadas
                     
            except json.JSONDecodeError as e:
                log_message("entGenApp.log",f"Error al parsear PK JSON: {e}")
                return None
            
            # Análisis de claves por tipo
            log_message("entGenApp.log","\n--- Análisis de claves en archivo ---")
            sphincs_count = 0
            dilithium_count = 0
            unknown_count = 0
            
            for idx, entry in enumerate(sk_data):
                algo = entry.get("algoritmo", "desconocido").lower()
                if algo == "sphincs":
                    sphincs_count += 1
                elif algo == "dilithium":
                    dilithium_count += 1
                    log_message("entGenApp.log",f"Dilithium #{idx+1}: {entry.get('titulo')} (ID: {entry.get('id')})")
                else:
                    unknown_count += 1
                    
            log_message("entGenApp.log",f"Total claves: {len(sk_data)} ({sphincs_count} SPHINCS, {dilithium_count} Dilithium, {unknown_count} desconocidas)")
            
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
                    
                    # Convertir claves a bytes con verificación detallada
                    try:
                        sk_hex = sk_entry.get("clave", "")
                        if not sk_hex:
                            log_message("entGenApp.log",f"  ERROR: Clave privada vacía para {titulo}")
                            continue
                        
                        log_message("entGenApp.log",f"  SK hex: {sk_hex[:50]}... ({len(sk_hex)} caracteres)")
                        
                        # Validar que solo contiene caracteres hexadecimales válidos
                        if not all(c in "0123456789abcdefABCDEF" for c in sk_hex):
                            log_message("entGenApp.log",f"  ERROR: Clave privada contiene caracteres no hexadecimales")
                            invalid_chars = [c for c in sk_hex if c not in "0123456789abcdefABCDEF"]
                            log_message("entGenApp.log",f"  Caracteres inválidos: {invalid_chars[:20]}...")
                            continue
                        
                        sk_bytes = bytes.fromhex(sk_hex)
                        log_message("entGenApp.log",f"  SK bytes: {sk_bytes[:10].hex()}... ({len(sk_bytes)} bytes)")
                        
                        # Similar para clave pública
                        pk_hex = pk_entry.get("clave", "")
                        if not pk_hex:
                            log_message("entGenApp.log",f"  ERROR: Clave pública vacía para {titulo}")
                            continue
                        
                        log_message("entGenApp.log",f"  PK hex: {pk_hex[:50]}... ({len(pk_hex)} caracteres)")
                        pk_bytes = bytes.fromhex(pk_hex)
                        log_message("entGenApp.log",f"  PK bytes: {pk_bytes[:10].hex()}... ({len(pk_bytes)} bytes)")
                        
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