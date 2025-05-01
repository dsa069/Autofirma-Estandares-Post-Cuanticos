from backend.funcComunes import log_message

def generar_claves_entidad(titulo, algoritmo, fecha_expedicion, fecha_caducidad, sk_path, pk_path):
    """
    Genera un nuevo par de claves de entidad y las guarda en los archivos correspondientes.
    
    Args:
        titulo (str): Nombre de la entidad
        algoritmo (str): 'sphincs' o 'dilithium'
        fecha_expedicion (str): Fecha de expedición en formato ISO
        fecha_caducidad (str): Fecha de caducidad en formato ISO
        sk_path (str): Ruta al archivo de claves privadas
        pk_path (str): Ruta al archivo de claves públicas
        
    Returns:
        key_id (str) : ID de la clave generada
    """
    try:
        # Generar ID único para esta clave
        import uuid
        key_id = str(uuid.uuid4())
        
        clave_base = {
            "id": key_id,
            "titulo": titulo,
            "algoritmo": algoritmo,
            "fecha_expedicion": fecha_expedicion,
            "fecha_caducidad": fecha_caducidad
        }
        
        sk, pk = generar_par_claves(algoritmo)

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
        
        import json
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
                        import datetime
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

def generar_certificado(clave_seleccionada, nombre, dni, password):
    """
    Genera certificados digitales para un usuario.
    """
    from backend.funcComunes import firmar_hash, calcular_hash_huella, calcular_hash_firma
    import datetime

    # Extracción de datos de la clave seleccionada
    algoritmo = clave_seleccionada["algoritmo"]
    entity_sk = clave_seleccionada["sk"]
    entity_pk_id = clave_seleccionada["id"]
    fecha_expedicion = datetime.date.today().isoformat()
    fecha_caducidad = clave_seleccionada["fecha_caducidad"]
    log_message("entGenApp.log", f"Generando certificados con algoritmo {algoritmo}")
    
    # Generar clave privada y pública del usuario según el algoritmo seleccionado
    user_sk, user_pk = generar_par_claves(algoritmo)
    log_message("entGenApp.log", f"Claves de usuario generadas con algoritmo {algoritmo}")

    # Crear estructura del certificado SIN la clave privada (para autenticación)
    certificado_autenticacion = {
        "nombre": nombre,
        "dni": dni,
        "fecha_expedicion": fecha_expedicion,
        "fecha_caducidad": fecha_caducidad,
        "user_public_key": user_pk.hex(),
        "entity_public_key_id": entity_pk_id,
        "algoritmo": algoritmo
    }

    # Calcular hash del certificado común y firmarlo
    hash_certificado = calcular_hash_firma(certificado_autenticacion)
    firma = firmar_hash(hash_certificado, entity_sk, algoritmo)

    # Añadir firma y calcular huella digital al certificado de autenticación
    certificado_autenticacion["firma"] = firma.hex()
    certificado_autenticacion["huella_digital"] = calcular_hash_huella(certificado_autenticacion)

    # Añadir clave privada encripatda y calcular huella digital al certificado de autenticación
    user_sk_encrypted = encrypt_private_key(user_sk, password)
    certificado_firma = certificado_autenticacion.copy()
    certificado_firma["user_secret_key"] = user_sk_encrypted
    certificado_firma["huella_digital"] = calcular_hash_huella(certificado_firma)

    # Guardar certificados usando el método dedicado
    return guardar_certificados(
                certificado_autenticacion, 
                certificado_firma, 
                dni, 
                algoritmo
            )
    
def encrypt_private_key(secret_key, password):
    """Cifra la clave privada con AES-256 en modo CBC usando una contraseña."""
    try:
        import secrets

        # Generar un salt aleatorio de 16 bytes
        salt = secrets.token_bytes(16)

        # Generar un hash de la contraseña con el salt para usarlo como clave AES (256 bits)
        import hashlib
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

        # Añadir padding con los últimos 50 bits duplicados
        padding = secret_key[-7:]  # 50 bits (aprox. 7 bytes)
        secret_key_padded = secret_key + padding

        # Generar un IV aleatorio de 16 bytes
        iv = secrets.token_bytes(16)

        # Crear el cifrador AES en modo CBC
        from Crypto.Cipher import AES # type: ignore
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Asegurar que el texto a cifrar es múltiplo de 16 bytes (padding PKCS7)
        pad_length = 16 - (len(secret_key_padded) % 16)
        secret_key_padded += bytes([pad_length] * pad_length)

        # Cifrar la clave privada
        encrypted_data = cipher.encrypt(secret_key_padded)

        # Guardar SALT + IV + datos cifrados en Base64 para facilitar almacenamiento
        import base64
        return base64.b64encode(salt + iv + encrypted_data).decode()

    except Exception as e:
        raise ValueError(f"Error al cifrar clave privada: {e}")

def generar_par_claves(algoritmo):
        # Generar las claves según el algoritmo seleccionado
        if algoritmo.lower() == "sphincs":
            from package.sphincs import Sphincs
            sphincs_inst = Sphincs()
            sk, pk = sphincs_inst.generate_key_pair()
        elif algoritmo.lower() == "dilithium":
            from dilithium_py.ml_dsa import ML_DSA_65 # type: ignore
            pk, sk = ML_DSA_65.keygen()
        else:
            return None
        
        return sk, pk
    
def guardar_certificados(certificado_autenticacion, certificado_firma, dni, algoritmo):
    """
    Guarda los certificados de autenticación y firma en archivos JSON.
    """
    import os

    # Crear carpeta de certificados en el directorio del usuario
    user_home = os.path.expanduser("~")
    certs_folder = os.path.join(user_home, "certificados_postC")
    
    # Crear la carpeta si no existe
    if not os.path.exists(certs_folder):
        os.makedirs(certs_folder)
    
    # Definir rutas de archivos
    cert_auth_path = os.path.join(certs_folder, f"certificado_digital_autenticacion_{dni}_{algoritmo.lower()}.json")
    cert_sign_path = os.path.join(certs_folder, f"certificado_digital_firmar_{dni}_{algoritmo.lower()}.json")
    import json

    # Guardar certificado de autenticación
    with open(cert_auth_path, "w") as cert_auth_file:
        json.dump(certificado_autenticacion, cert_auth_file, indent=4)

    # Guardar certificado de firma
    with open(cert_sign_path, "w") as cert_sign_file:
        json.dump(certificado_firma, cert_sign_file, indent=4)

    log_message("entGenApp.log", f"Certificados guardados en:\n- {cert_auth_path}\n- {cert_sign_path}")
    
    return cert_auth_path, cert_sign_path

def cargar_json(ruta_archivo):      
    """Carga un archivo JSON o crea uno nuevo y devuelve lista vacía."""
    import os
    import json
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

def convert_to_iso_date(date_str):
    """Valida una fecha en formato DD/MM/AAAA y la convierte a formato ISO."""
    try:
        import datetime

        day, month, year = map(int, date_str.split('/'))
        date_obj = datetime.date(year, month, day)
        return date_obj.isoformat()
    except (ValueError, TypeError):
        return None

def clasificar_claves_por_estado(claves_disponibles):
    """
    Clasifica las claves disponibles por su estado de validez temporal
    """
    from datetime import datetime
    fecha_actual = datetime.now()
    
    # Listas para clasificar las claves
    claves_vigentes = []    # En fecha (expedidas y no caducadas)
    claves_futuras = []     # Fecha de expedición futura
    claves_caducadas = []   # Caducadas
    
    # Procesar cada tipo de clave y clasificarlas
    for algoritmo in ["sphincs", "dilithium"]:
        for clave in claves_disponibles.get(algoritmo, []):
            try:
                fecha_exp = datetime.fromisoformat(clave["fecha_expedicion"])
                fecha_cad = datetime.fromisoformat(clave["fecha_caducidad"])
                
                # Clasificar la clave según su estado
                if fecha_cad < fecha_actual:
                    # Clave caducada
                    claves_caducadas.append((algoritmo, clave, True, False))
                elif fecha_exp > fecha_actual:
                    # Clave futura (no válida aún)
                    claves_futuras.append((algoritmo, clave, False, True))
                else:
                    # Clave vigente
                    claves_vigentes.append((algoritmo, clave, False, False))
            except Exception:
                # Si hay error en fechas, considerarla como vigente
                claves_vigentes.append((algoritmo, clave, False, False))
    
    # Ordenar cada grupo por título
    claves_vigentes.sort(key=lambda x: x[1].get("titulo", "").lower())
    claves_futuras.sort(key=lambda x: x[1].get("titulo", "").lower())
    claves_caducadas.sort(key=lambda x: x[1].get("titulo", "").lower())
    
    # Combinar en el orden deseado: vigentes → futuras → caducadas
    return claves_vigentes + claves_futuras + claves_caducadas

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
    
def verificar_campos_generacion_claves(titulo, fecha_ini_str, fecha_cad_str, algoritmo):
    """
    Verifica que los campos para generar una nueva clave sean válidos.
    
    Args:
        titulo (str): Nombre o título de la entidad
        fecha_ini_str (str): Fecha de inicio en formato DD/MM/AAAA
        fecha_cad_str (str): Fecha de caducidad en formato DD/MM/AAAA
        
    Returns:
        tuple: Mensaje de error o éxito, fecha de expedición y fecha de caducidad
    """
    from datetime import datetime, date
    # Validar título
    if not titulo or not titulo.strip():
        return "Debe especificar un nombre para la entidad", None, None
    
    if algoritmo.upper() not in ["SPHINCS", "DILITHIUM"]:
        return "Debe especificar el algoritmo de frima SPHINCS o DILITHIUM", None, None

    # Validar fechas
    fecha_expedicion = convert_to_iso_date(fecha_ini_str)
    if not fecha_expedicion:
        return "Fecha de inicio inválida. Use formato DD/MM/AAAA", None, None
        
    fecha_caducidad = convert_to_iso_date(fecha_cad_str)
    if not fecha_caducidad:
        return "Fecha de caducidad inválida. Use formato DD/MM/AAAA", None, None
        
    # Verificar que la fecha de caducidad sea posterior a la de expedición
    if fecha_caducidad < fecha_expedicion:
        return "La fecha de caducidad debe ser posterior a la fecha de inicio", None, None
    
    fecha_expedicion_dt = date.fromisoformat(fecha_expedicion)
    if datetime.now().date() > fecha_expedicion_dt:
        return "La fecha de expedicion debe ser posterior a la fecha actual", None, None
    
    # Si todo está correcto, devolver datos validados
    return "Datos válidos", fecha_expedicion, fecha_caducidad
    
def validar_datos_usuario(nombre, dni):
    """
    Valida que los datos básicos del usuario sean correctos.
    
    Args:
        nombre (str): Nombre del usuario
        dni (str): DNI/NIE/CIF del usuario
    
    Returns:
        tuple: (bool, str) - (éxito, mensaje_error)
    """
    import re
    
    if not nombre or not dni:
        return False, "El nombre y el DNI/NIE/CIF son obligatorios."
        
    # Patrones para NIF, NIE y CIF
    patron_nif = r'^[0-9]{8}[A-Z]$'
    patron_nie = r'^[XYZ][0-9]{7}[A-Z]$'
    patron_cif = r'^[A-HJPQSUVNW][0-9]{7}[A-J0-9]$'
    
    # Letras de control para NIF/NIE
    letras_nif = 'TRWAGMYFPDXBNJZSQVHLCKE'
    
    if re.match(patron_nif, dni):
        # Validar NIF
        numero = int(dni[0:8])
        letra_control = dni[8]
        indice = numero % 23
        letra_calculada = letras_nif[indice]
        
        if letra_calculada != letra_control:
            return False, f"NIF no válido. La letra de control no es correcta."
        
        return True, ""
        
    elif re.match(patron_nie, dni):
        # Validar NIE
        primera_letra = dni[0]
        if primera_letra == 'X':
            numero = int('0' + dni[1:8])
        elif primera_letra == 'Y':
            numero = int('1' + dni[1:8])
        elif primera_letra == 'Z':
            numero = int('2' + dni[1:8])
        
        letra_control = dni[8]
        indice = numero % 23
        letra_calculada = letras_nif[indice]
        
        if letra_calculada != letra_control:
            return False, f"NIE no válido. La letra de control no es correcta."
        
        return True, ""
        
    elif re.match(patron_cif, dni):
        # Validación completa de CIF con cálculo de dígito de control
        primera_letra = dni[0]
        digitos_centrales = dni[1:8]
        digito_control = dni[8]
        
        # Determinar si el control debe ser letra o número
        control_debe_ser_letra = primera_letra in "PQRSNW"
        control_debe_ser_numero = primera_letra in "ABEH"
        # Para las demás letras puede ser cualquiera
        
        # Calcular el dígito de control
        # A: Suma de dígitos en posiciones pares
        suma_pares = int(digitos_centrales[1]) + int(digitos_centrales[3]) + int(digitos_centrales[5])        
        # B: Procesar dígitos en posiciones impares
        suma_impares = 0
        for i in [0, 2, 4, 6]:
            producto = int(digitos_centrales[i]) * 2
            suma_impares += (producto // 10) + (producto % 10)  # Suma de dígitos del producto
        
        # C: Suma total
        suma_total = suma_pares + suma_impares
        
        # E: Dígito de las unidades
        digito_unidades = suma_total % 10
        
        # D: Valor final para control
        if digito_unidades != 0:
            valor_control = 10 - digito_unidades
        else:
            valor_control = 0
            
        # Mapeo de valores a letras para control
        letras_cif = "JABCDEFGHI"
        letra_control = letras_cif[valor_control]
        
        # Validar el dígito de control
        if control_debe_ser_letra:
            if digito_control != letra_control:
                return False, f"CIF no válido. La letra de control no es correcta."
        elif control_debe_ser_numero:
            if digito_control != str(valor_control):
                return False, f"CIF no válido. El dígito de control no es correcto."
        else:
            # Para los demás casos, puede ser letra o número
            if digito_control != str(valor_control) and digito_control != letra_control:
                return False, f"CIF no válido. Los dígitos de control de control no son correctos."
        
        return True, ""
    
    else:
        return False, "El formato del documento no es válido. Debe ser un NIF, NIE o CIF."
