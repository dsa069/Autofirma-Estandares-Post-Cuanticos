from datetime import datetime, timedelta
import json
import os
import fitz  # type: ignore # PyMuPDF
from backend.funcComunes import log_message

BASE_DIR = None

def set_base_dir_back_firma(base_dir):
    global BASE_DIR
    BASE_DIR = base_dir

def firmar_documento_pdf(save_path, user_sk, cert_firma, cert_auth, visual_signature_hash=None):
    """
    Firma digitalmente un documento PDF.
    """
    try:
        from backend.funcComunes import firmar_hash
        # CALCULAR HASH DEL DOCUMENTO
        hash_documento = calcular_hash_documento(save_path)
        log_message("firmaApp.log", f"Hash del documento: {hash_documento.hex()}")

        # OBTENER EL ALGORITMO DEL CERTIFICADO
        algoritmo = cert_firma.get("algoritmo", "sphincs")
        log_message("firmaApp.log", f"Firmando con algoritmo: {algoritmo.upper()}")

        # FIRMAR EL HASH DEL DOCUMENTO
        signature = firmar_hash(hash_documento, user_sk, algoritmo)

        # AÑADIR METADATOS AL PDF (incluida la firma digital)
        add_metadata_to_pdf(save_path, signature, cert_auth, user_sk, visual_signature_hash)

        # Registrar en el log el documento firmado
        titulo_doc = os.path.basename(save_path)
        nombre_certificado = cert_firma["nombre"]
        log_message("firmaApp.log", f"Documento firmado: '{titulo_doc}' | Hash: {hash_documento.hex()} | Firmante: {nombre_certificado}")
        
        return True, f"Documento firmado correctamente y guardado en:\n{save_path}"
        
    except Exception as e:
        log_message("firmaApp.log", f"Error al firmar documento: {e}")
        return False, f"Error al firmar documento: {e}"

def añadir_firma_visual_pdf(pdf_path, pagina, posicion, signature_width, signature_height, nombre_certificado):
    """
    Añade una firma visual al PDF con un enlace clickable para verificación.
    Returns:
        tuple: (success, visual_signature_hash)
    """
    try:
        # Guardar el documento antes de añadir la firma visual para calcular el hash "antes"
        doc_before = fitz.open(pdf_path)
        hash_before = calcular_hash_documento(pdf_path)
        doc_before.close()

        doc = fitz.open(pdf_path)
        page = doc[pagina]
        x, y = posicion
        rect = fitz.Rect(x, y, x + signature_width, y + signature_height)
        
        signature_text = f"Firmado digitalmente por: {nombre_certificado}"
        signature_date = f"Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"
        
        # Firma en blanco y negro
        page.draw_rect(rect, color=(0, 0, 0), fill=(1, 1, 1), width=1, overlay=True)  # Fondo blanco, borde negro
        
        text_point = fitz.Point(x + 5, y + 15)
        page.insert_text(text_point, signature_text, fontsize=8, color=(0, 0, 0), overlay=True)  # Texto negro
        
        text_point = fitz.Point(x + 5, y + 25)
        page.insert_text(text_point, signature_date, fontsize=8, color=(0, 0, 0), overlay=True)  # Texto negro

        crear_enlace_verificacion(page, rect, pdf_path)

        doc.save(pdf_path, incremental=True, encryption=0)
        doc.close()

        # Calcular el hash "después" de añadir la firma visual
        doc_after = fitz.open(pdf_path)
        hash_after = calcular_hash_documento(pdf_path)
        doc_after.close()
        
        # alcular el hash de la DIFERENCIA entre antes y después
        # Esto representará más precisamente la firma visual por sí sola
        visual_signature_hash = bytes(a ^ b for a, b in zip(hash_before, hash_after))

        log_message("firmaApp.log",f"Firma visual añadida en la página {pagina+1}")
        return True, visual_signature_hash
        
    except Exception as e:
        log_message("firmaApp.log",f"Error al añadir firma visual: {e}")
        return False, None

def verificar_firma(hash_data, clave_pública, firma, algoritmo):
    from package.sphincs import Sphincs
    # Firmar según el algoritmo seleccionado
    if algoritmo.lower() == "sphincs":
        sphincs = Sphincs()
        firma = sphincs.verify(hash_data, firma, clave_pública)
    elif algoritmo.lower() == "dilithium":
        from dilithium_py.ml_dsa import ML_DSA_65  # type: ignore # Usamos ML_DSA_65 (Dilithium3)
        firma = ML_DSA_65.verify(clave_pública, hash_data, firma)
    else:
        return None
    return firma

def verificar_firmas_cascada(firmas, hash_actual):  
# IMPORTANTE: Procesar firmas en orden inverso para la validación en cascada
    total_firmas = len(firmas)
    
    # Lista para almacenar los resultados de validación
    resultados_validacion = []
    
    # FASE 1: Procesar las firmas de la más reciente a la más antigua
    log_message("firmaApp.log","Iniciando verificación en cascada de firmas...")
    for i in range(total_firmas - 1, -1, -1):
        firma_data = firmas[i]

        # Extraer datos básicos
        firma = bytes.fromhex(firma_data["firma"])
        cert_data = firma_data["certificado_autenticacion"]
        algoritmo = cert_data.get("algoritmo", "sphincs").lower()
        user_pk = bytes.fromhex(cert_data["user_public_key"])
        firma_metadatos = bytes.fromhex(firma_data["firma_metadatos"])
        
        # Validar firma metadatos
        hash_recalculado_meta = calcular_hash_metadatos(firma_data)
        
        integridad_valida = verificar_firma(hash_recalculado_meta, user_pk, firma_metadatos, algoritmo)
        if not integridad_valida:
            log_message("firmaApp.log", f"ALERTA: La integridad de los metadatos de la firma {i} ha sido comprometida")
        
        # Verificar certificado
        cert_valido = verificar_certificado(cert_data)
        
        # Verificar firma usando el hash actual
        firma_valida = verificar_firma(hash_actual, user_pk, firma, algoritmo)
        
        # Guardar el resultado
        resultados_validacion.append({
            "indice": i,
            "firma_valida": firma_valida,
            "cert_valido": cert_valido,
            "integridad_valida": integridad_valida,
            "hash_verificacion": hash_actual,
            "firma_data": firma_data
        })
        
        # Calcular el siguiente hash para la cascada si hay más firmas para verificar
        if i > 0 and "hash_firma_visual" in firma_data:
            hash_visual = bytes.fromhex(firma_data["hash_firma_visual"])
            # Operación "resta" conceptual para obtener el hash anterior
            hash_actual = bytes(a ^ b for a, b in zip(hash_actual, hash_visual))
            log_message("firmaApp.log",f"Hash calculado para firma {i}: {hash_actual.hex()[:10]}...")

    resultados_validacion.reverse()
    return resultados_validacion

def extraer_firmas_documento(file_path):
    """
    Extrae los metadatos y firmas de un documento PDF.
    """
    try:
        # Extraer metadatos del PDF
        doc = fitz.open(file_path)
        metadata = doc.metadata
        doc.close()

        # Extraer firmas
        meta_data = json.loads(metadata.get("keywords", "{}"))
        
        # Verificar si hay firmas
        firmas = meta_data.get("firmas", [])
        if not firmas:
            log_message("firmaApp.log", "No se encontraron firmas en el documento.")
            return False, None, None
                
        # Calcular el hash del documento actual
        hash_documento_actual = calcular_hash_documento(file_path)
        
        return True, firmas, hash_documento_actual

    except Exception as e:
        log_message("firmaApp.log", f"Error al extraer firmas: {e}")
        return False, None, None

def determinar_estilo_firmas_validadas(valid_count, invalid_count):
    if invalid_count == 0 and valid_count > 0:
        return (
            "tick",
            f"El documento posee firmas válidas"
        )
    elif valid_count == 0:
        return (
            "error",
            f"Las firmas del documento no son válidas"
        )
    else:
        return (
            "caution",
            f"Algunas del documento firmas son inválidas"
        )

def verificar_certificado(cert_data):
    """Verifica la validez de un certificado (SPHINCS+ o Dilithium)."""
    try:
        from backend.funcComunes import calcular_hash_firma, calcular_hash_huella
        # Detectar algoritmo del certificado
        algoritmo = cert_data.get("algoritmo")
        log_message("firmaApp.log",f"Verificando certificado con algoritmo: {algoritmo.upper()}")
        
        expected_hash = cert_data.get("huella_digital")
        firma = cert_data.get("firma")

        # -------------------- VALIDACIÓN HUELLA DIGITAL --------------------
        cert_copy = cert_data.copy()

        if calcular_hash_huella(cert_copy) != expected_hash:
            raise ValueError("La huella digital del certificado no es válida.")
        # -------------------- VERIFICACIÓN DE FECHAS --------------------
        fecha_expedicion = datetime.fromisoformat(cert_data["fecha_expedicion"])
        fecha_caducidad = datetime.fromisoformat(cert_data["fecha_caducidad"])
        current_date = datetime.now()
        
        if current_date < fecha_expedicion:
            raise ValueError("El certificado aún no es válido (fecha de emisión futura).")

        if current_date > fecha_caducidad:
            raise ValueError("El certificado ha expirado.")
        
        # -------------------- VERIFICACIÓN PK ENTIDAD --------------------
        entity_pk_id = cert_data.get("entity_public_key_id")
        
        if not entity_pk_id:
            raise ValueError("El certificado no contiene un ID de clave pública de entidad válido.")
        
        # Obtener la clave pública usando la función centralizada
        entity_pk = buscar_clave_publica_por_id(entity_pk_id, algoritmo)
        
        if entity_pk is None:
            raise ValueError(f"No se encontró una clave pública válida con ID {entity_pk_id}")
            
        # -------------------- VALIDACIÓN FIRMA --------------------
        recalculated_hash_firma = calcular_hash_firma(cert_copy)

        # Convertir la firma a bytes
        firma_bytes = bytes.fromhex(firma)
        
        # Verificar firma según el algoritmo usado
        firma_valida = verificar_firma(recalculated_hash_firma, entity_pk, firma_bytes, algoritmo)


        if not firma_valida:
            raise ValueError("La firma del certificado no es válida.")

        return True
    except Exception as e:
        log_message("firmaApp.log",f"Error al verificar certificado: {e}")
        return False

def cargar_datos_certificado(cert_path):
    """Carga y verifica un certificado desde el archivo especificado"""
    try:
        # Leer el certificado
        with open(cert_path, "r") as cert_file:
            cert_data = json.load(cert_file)

        # Verificar el certificado
        if not verificar_certificado(cert_data):
            log_message("firmaApp.log", "Certificado no válido")
            return False, cert_data, None, None, None, None
        
        # Extraer datos básicos
        user_pk = bytes.fromhex(cert_data["user_public_key"])
        exp_date = datetime.fromisoformat(cert_data["fecha_caducidad"])
        issue_date = datetime.fromisoformat(cert_data["fecha_expedicion"])
        algoritmo = cert_data.get("algoritmo")
        entity_pk_id = cert_data["entity_public_key_id"]
        ent_pk = buscar_clave_publica_por_id(entity_pk_id, algoritmo)
        
        return True, cert_data, user_pk, ent_pk, exp_date, issue_date
    except Exception as e:
        log_message("firmaApp.log", f"Error al cargar datos del certificado: {e}")
        return False, cert_data, None, None, None, None

def cargar_certificado_autenticacion(cert_firma):
    """
    Carga automáticamente el certificado de autenticación correspondiente al certificado de firma.
    """
    try:
        from backend.funcComunes import calcular_hash_firma
        # Extraer DNI y algoritmo del certificado de firma
        dni = cert_firma["dni"]
        algoritmo = cert_firma["algoritmo"].lower()
        
        # Buscar automáticamente el certificado de autenticación correspondiente
        user_home = os.path.expanduser("~")
        certs_folder = os.path.join(user_home, "certificados_postC")
        cert_auth_path = os.path.join(certs_folder, f"certificado_digital_autenticacion_{dni}_{algoritmo}.json")
        
        # Verificar si existe el certificado de autenticación
        if not os.path.exists(cert_auth_path):
            error_msg = f"No se encontró el certificado de autenticación para el DNI {dni}."
            log_message("firmaApp.log", f"Error: No se encontró certificado de autenticación para DNI {dni}")
            return False, None, error_msg
            
        # Cargar el certificado de autenticación
        try:
            with open(cert_auth_path, "r") as cert_file:
                cert_auth = json.load(cert_file)
                
            # Verificar el certificado de autenticación
            if not verificar_certificado(cert_auth):
                error_msg = "El certificado de autenticación no es válido."
                log_message("firmaApp.log", "Error: Certificado de autenticación inválido.")
                return False, None, error_msg
                
            log_message("firmaApp.log", f"Certificado de autenticación cargado automáticamente para DNI: {dni}")

            # CALCULAR HASH DE LA FIRMA DE LOS CERTIFICADOS
            hash_firma_cd = calcular_hash_firma(cert_firma)
            hash_auth_cd = calcular_hash_firma(cert_auth)

            if hash_firma_cd != hash_auth_cd:
                error_msg = "Los certificados de firma y autenticación no están asociados."
                log_message("firmaApp.log", "Error: Los certificados de firma y autenticación no coinciden.")
                return False, None, error_msg
                
            return True, cert_auth, None
                
        except Exception as e:
            error_msg = f"Error al cargar certificado de autenticación: {e}"
            log_message("firmaApp.log", error_msg)
            return False, None, error_msg
            
    except Exception as e:
        error_msg = f"Error procesando certificado de autenticación: {e}"
        log_message("firmaApp.log", error_msg)
        return False, None, error_msg

def enviar_alerta_certificado(nombre, dni):
    """Muestra una alerta simple en la consola cuando hay intentos fallidos."""
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message("firmaApp.log",f"[{timestamp}] ALERTA: Intentos fallidos para {nombre} ({dni})")
    log_message("firmaApp.log","-" * 50)
    
    return True

def calcular_hash_documento(file_path):
    """Calcula el hash SHA-256 del contenido del documento, ignorando los metadatos."""
    try:
        doc = fitz.open(file_path)

        # Extraer solo los bytes de las páginas, ignorando metadatos
        contenido_binario = b"".join(doc[page].get_text("text").encode() for page in range(len(doc)))

        doc.close()

        import hashlib
        return hashlib.sha256(contenido_binario).digest()
    
    except Exception as e:
        raise ValueError(f"Error al calcular el hash del documento: {e}")
    
def calcular_hash_metadatos(metadata):
    """ordered_keys de la huella digital del certificado."""
    from backend.funcComunes import calcular_hash_ordenado
    ordered_keys = [
        "firma",
        "certificado_autenticacion",
        "fecha_firma",
        "hash_firma_visual"
    ]
    return calcular_hash_ordenado(metadata, ordered_keys).digest() 

def decrypt_private_key(encrypted_sk, password):
        """Descifra la clave privada utilizando AES-256 CBC y verifica la redundancia."""
        try:
            import base64
            encrypted_data = base64.b64decode(encrypted_sk)  # Decodificar de Base64

            # Extraer SALT (primeros 16 bytes)
            salt = encrypted_data[:16]
            
            # Extraer IV (siguientes 16 bytes)
            iv = encrypted_data[16:32]
            
            # Derivar clave con el salt
            import hashlib
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

            from Crypto.Cipher import AES # type: ignore
            cipher = AES.new(key, AES.MODE_CBC, iv)  # Crear cifrador AES-CBC

            decrypted_sk = cipher.decrypt(encrypted_data[32:])  # Desencriptar
            decrypted_sk = decrypted_sk[:-decrypted_sk[-1]]  # Eliminar padding PKCS7

            # Verificar redundancia (últimos 50 bits = 7 bytes deben repetirse al final)
            if decrypted_sk[-7:] != decrypted_sk[-14:-7]:
                raise ValueError("Contraseña incorrecta: No se validó la redundancia.")

            return decrypted_sk[:-7]  # Devolver clave privada sin redundancia

        except Exception:
            return None  # Error → Contraseña incorrecta    

def buscar_clave_publica_por_id(entity_pk_id, algoritmo):
    """
    Busca una clave pública en el archivo pk_entidad.json por su ID.
    """
    import os
    import json
    
    # Ruta al archivo de claves públicas de entidad
    pk_path = os.path.join(BASE_DIR, "pk_entidad.json")
    
    try:
        # Cargar el archivo de claves
        with open(pk_path, 'r') as f:
            pk_data = json.load(f)
        
        # Buscar la clave por ID
        for pk_entry in pk_data:
            if pk_entry.get("id") == entity_pk_id:
                # Verificar que coincida el algoritmo
                if algoritmo and pk_entry.get("algoritmo", "").lower() == algoritmo.lower():
                    try:
                        entity_pk = bytes.fromhex(pk_entry.get("clave", ""))
                        log_message("firmaApp.log", f"Clave pública de entidad encontrada: {pk_entry.get('titulo', 'Sin título')}")
                        return entity_pk
                    except Exception as e:
                        log_message("firmaApp.log", f"Error al procesar clave: {e}")
        
        # Si no se encontró la clave
        log_message("firmaApp.log", f"No se encontró la clave pública con ID {entity_pk_id}")
        return None
        
    except Exception as e:
        log_message("firmaApp.log", f"Error al cargar archivo de claves públicas: {e}")
        return None

def add_metadata_to_pdf(pdf_path, firma, cert_data, user_sk, visual_signature_hash=None):
    """Añade la firma y el certificado de autenticación a los metadatos del PDF preservando firmas anteriores."""
    try:
        from backend.funcComunes import firmar_hash

        doc = fitz.open(pdf_path)
        metadata = doc.metadata
        fecha_firma = datetime.now().isoformat()
        
        # Nueva entrada de firma
        nueva_firma = {
            "firma": firma.hex(),
            "certificado_autenticacion": cert_data,
            "fecha_firma": fecha_firma
        }

        # Añadir el hash de la firma visual si existe
        if visual_signature_hash:
            nueva_firma["hash_firma_visual"] = visual_signature_hash.hex()

        # Calcular y añadir el hash de integridad
        hash_integridad = calcular_hash_metadatos(nueva_firma)

        nueva_firma["firma_metadatos"] = firmar_hash(hash_integridad, user_sk, cert_data["algoritmo"]).hex()
        
        # Verificar si ya existen metadatos de firmas
        existing_metadata = {}
        if "keywords" in metadata and metadata["keywords"]:
            try:
                existing_metadata = json.loads(metadata["keywords"])
            except json.JSONDecodeError:
                existing_metadata = {}
        
        # Verificar si ya existe un array de firmas
        if "firmas" in existing_metadata:
            # Añadir la nueva firma al array existente
            existing_metadata["firmas"].append(nueva_firma)
        else:
            # Crear un nuevo array con la primera firma
            existing_metadata["firmas"] = [nueva_firma]
        
        # Actualizar los metadatos
        metadata["keywords"] = json.dumps(existing_metadata, separators=(',', ':'))
        
        doc.set_metadata(metadata)
        doc.save(pdf_path, incremental=True, encryption=0)
        doc.close()
        
        log_message("firmaApp.log",f"PDF firmado con metadatos guardado en: {pdf_path}")
        
    except Exception as e:
        log_message("firmaApp.log",f"Error al añadir metadatos al PDF: {e}") 
        raise 

def copiar_contenido_pdf(origen, destino):
    """
    Copia el contenido de un archivo PDF de origen a un archivo de destino.
    """
    try:
        with open(destino, "wb") as f:
            with open(origen, "rb") as original_file:
                f.write(original_file.read())  # Copiar el contenido original
        return True
    except Exception as e:
        log_message("firmaApp.log", f"Error al copiar contenido PDF: {e}")
        return False

def detect_active_pdf():
    """Detecta automáticamente el PDF activo incluso cuando esta app está en primer plano"""
    try:
        log_message("firmaApp.log","Intentando detectar el PDF activo...")
        import sys
        if sys.platform == "win32":
            try:
                import psutil # type: ignore
                import glob
                
                # Estrategia 1: Buscar PDFs abiertos por cualquier proceso de visor PDF
                log_message("firmaApp.log","Buscando PDFs abiertos en procesos activos...")
                pdf_viewers = ["acrord32.exe", "acrobat.exe", "chrome.exe", "msedge.exe", 
                            "firefox.exe", "SumatraPDF.exe", "FoxitReader.exe"]
                
                pdf_files_found = []
                
                # Buscar en todos los procesos, no solo el activo
                for proc in psutil.process_iter(['pid', 'name']):
                    if any(viewer.lower() in proc.info['name'].lower() for viewer in pdf_viewers):
                        try:
                            p = psutil.Process(proc.info['pid'])
                            for file in p.open_files():
                                if file.path.lower().endswith('.pdf'):
                                    pdf_files_found.append((file.path, p.create_time()))
                                    log_message("firmaApp.log",f"PDF encontrado en proceso {p.name()}: {file.path}")
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            continue
                
                # Si encontramos PDFs, devolver el más reciente
                if pdf_files_found:
                    # Ordenar por tiempo de creación del proceso, más reciente primero
                    pdf_files_found.sort(key=lambda x: x[1], reverse=True)
                    log_message("firmaApp.log",f"PDF seleccionado (proceso más reciente): {pdf_files_found[0][0]}")
                    return pdf_files_found[0][0]
                
                # Estrategia 2: Buscar PDFs recientemente modificados
                log_message("firmaApp.log","Buscando PDFs recientemente modificados...")
                recent_files = []
                locations = [
                    os.path.join(os.path.expanduser("~"), "Desktop"),
                    os.path.join(os.path.expanduser("~"), "Documents"),
                    os.path.join(os.path.expanduser("~"), "Downloads"),
                    "C:\\Temp",
                    os.environ.get('TEMP', '')
                ]
                
                # Buscar PDFs modificados en los últimos 5 minutos
                cutoff_time = datetime.now() - timedelta(minutes=5)
                
                for location in locations:
                    if os.path.exists(location):
                        for root, _, files in os.walk(location):
                            for file in files:
                                if file.lower().endswith('.pdf'):
                                    file_path = os.path.join(root, file)
                                    try:
                                        mtime = os.path.getmtime(file_path)
                                        mtime_dt = datetime.fromtimestamp(mtime)
                                        if mtime_dt > cutoff_time:
                                            recent_files.append((file_path, mtime_dt))
                                    except:
                                        pass
                
                # Si encontramos archivos recientes, devolver el más reciente
                if recent_files:
                    recent_files.sort(key=lambda x: x[1], reverse=True)
                    log_message("firmaApp.log",f"PDF seleccionado (modificado recientemente): {recent_files[0][0]}")
                    return recent_files[0][0]
                
                # Estrategia 3: Buscar en archivos temporales de navegadores
                log_message("firmaApp.log","Buscando PDFs en archivos temporales...")
                temp_files = []
                
                # Ubicaciones típicas de archivos temporales de navegadores
                browser_temp_locations = [
                    os.path.join(os.environ.get('TEMP', ''), '*'),
                    os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data', 'Default', 'Cache', '*'),
                    os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Edge', 'User Data', 'Default', 'Cache', '*')
                ]
                
                for pattern in browser_temp_locations:
                    for file_path in glob.glob(pattern):
                        if os.path.isfile(file_path):
                            try:
                                with open(file_path, 'rb') as f:
                                    # Leer los primeros bytes para comprobar si es un PDF
                                    header = f.read(4)
                                    if header == b'%PDF':
                                        mtime = os.path.getmtime(file_path)
                                        temp_files.append((file_path, mtime))
                            except:
                                pass
                
                if temp_files:
                    temp_files.sort(key=lambda x: x[1], reverse=True)
                    log_message("firmaApp.log",f"PDF temporal seleccionado: {temp_files[0][0]}")
                    return temp_files[0][0]
                
                # No se pudo encontrar ningún PDF activo
                log_message("firmaApp.log","No se pudo detectar automáticamente el PDF activo")
                return None
                
            except ImportError as e:
                log_message("firmaApp.log",f"Error: módulo necesario no instalado: {e}")
                log_message("firmaApp.log","Para detección automática, instale los paquetes requeridos:")
                log_message("firmaApp.log","pip install pywin32 psutil")
                return None
        else:
            log_message("firmaApp.log","Detección automática solo disponible en Windows")
            return None
    except Exception as e:
        log_message("firmaApp.log",f"Error en detección automática: {e}")
        import traceback
        log_message("firmaApp.log",traceback.format_exc())
        return None

def crear_enlace_verificacion(page, rect, pdf_path):
    """
    Crea un enlace de verificación en el PDF que redirecciona al protocolo autofirma://
    """
    try:
        # Prepare the encoded path and URI 
        uri = "autofirma://CURRENT_PDF"
        
        # Añadir un enlace HTTP que redirige al protocolo personalizado
        # Esta técnica es mejor aceptada por Chrome
        html_redirect = f'''
        <html>
        <head>
            <meta http-equiv="refresh" content="0;url={uri}">
            <title>Redirigiendo a AutoFirma</title>
        </head>
        <body>
            <p>Verificando firma... si no se abre automáticamente, 
            <a href="{uri}">haga clic aquí</a>.</p>
        </body>
        </html>
        '''
        
        # Generar un nombre único para el archivo HTML basado en la ruta del PDF
        import hashlib
        pdf_hash = hashlib.md5(pdf_path.encode()).hexdigest()[:10]
        pdf_basename = os.path.basename(pdf_path).replace(".", "_")
        
        # Guardar la página de redirección en el directorio temporal con nombre único
        temp_dir = os.path.join(os.path.expanduser("~"), "temp_autofirma")
        os.makedirs(temp_dir, exist_ok=True)
        
        # Usar nombre único para cada redirección
        redirect_path = os.path.join(temp_dir, f"redirect_{pdf_basename}_{pdf_hash}.html")
        
        with open(redirect_path, "w") as f:
            f.write(html_redirect)
        
        # Usar una URL file:// para abrir la página HTML
        redirect_uri = f"file:///{redirect_path.replace('\\', '/')}"
        
        # Insertar el enlace que apunta a la página de redirección
        page.insert_link({
            "kind": fitz.LINK_URI,
            "from": rect,
            "uri": redirect_uri
        })
        
        log_message("firmaApp.log", f"Firma clickable creada para {os.path.basename(pdf_path)}")
        return True
        
    except Exception as e:
        log_message("firmaApp.log", f"Error al añadir enlace: {e}")
        return False

def register_protocol_handler():
    try:
        import sys
        if sys.platform != "win32":
            log_message("firmaApp.log","Registro de protocolo solo disponible en Windows")
            return False
            
        import winreg
        
        # Obtener ruta del ejecutable actual
        if getattr(sys, 'frozen', False):
            exe_path = sys.executable  # Si es ejecutable compilado
        else:
            exe_path = f'"{sys.executable}" "{os.path.abspath(__file__)}"'  # Python + script
            
        # Registrar protocolo autofirma://
        key_name = r"Software\Classes\autofirma"
        
        # Crear clave principal
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_name)
        winreg.SetValue(key, "", winreg.REG_SZ, "URL:AutoFirma Protocol")
        winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")
        
        # Crear comando (añadir comillas para asegurar que se interpreta correctamente)
        cmd_key = winreg.CreateKey(key, r"shell\open\command")
        
        # CAMBIO: Encerrar el argumento %1 entre comillas para evitar problemas con espacios
        winreg.SetValue(cmd_key, "", winreg.REG_SZ, f'{exe_path} --verify "%1"')
        
        winreg.CloseKey(cmd_key)
        winreg.CloseKey(key)
        
        log_message("firmaApp.log","Protocolo 'autofirma://' registrado correctamente")
        return True
    except Exception as e:
        log_message("firmaApp.log",f"Error al registrar protocolo: {e}")
        return False
    


def process_uri(uri):
    """Extrae la ruta del PDF desde una URI autofirma:// y verifica el documento"""
    try:
        log_message("firmaApp.log", f"Procesando URI: {uri}")
        
        # Validar formato de la URI
        if not uri.startswith("autofirma://"):
            log_message("firmaApp.log", "El formato de la URI no es válido.")
            return False, None
        
        # Extraer la ruta codificada
        encoded_path = uri[len("autofirma://"):].rstrip('/')
        
        # Obtener la ruta del archivo
        file_path = None
        
        # Caso especial: detectar PDF activo
        if encoded_path.upper() == "CURRENT_PDF":
            file_path = detect_active_pdf()
            if not file_path:
                log_message("firmaApp.log", "No se pudo detectar automáticamente el PDF activo.")
                return False, None
            log_message("firmaApp.log", f"PDF activo detectado: {file_path}")
        
        # Caso normal: decodificar ruta
        else:
            try:
                import base64
                file_path = base64.urlsafe_b64decode(encoded_path.encode()).decode()
            except Exception:
                log_message("firmaApp.log", "No se pudo decodificar la ruta del PDF.")
                return False, None
        
        # Verificar existencia del archivo
        if not os.path.exists(file_path):
            log_message("firmaApp.log", f"No se encuentra el archivo: {file_path}")
            return False, None
        
        return True, file_path
        
    except Exception as e:
        log_message("firmaApp.log", f"Error al verificar desde URI: {e}")
        return False, None