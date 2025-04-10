import base64
from datetime import datetime, timedelta
import hashlib
import json
import os
import sys
import fitz  # PyMuPDF
from Crypto.Cipher import AES
from backend.funcComunes import firmar_hash, log_message, calcular_hash_firma, calcular_hash_huella

def calcular_hash_documento(file_path):
    """Calcula el hash SHA-256 del contenido del documento, ignorando los metadatos."""
    try:
        doc = fitz.open(file_path)

        # Extraer solo los bytes de las páginas, ignorando metadatos
        contenido_binario = b"".join(doc[page].get_text("text").encode() for page in range(len(doc)))

        doc.close()
        
        return hashlib.sha256(contenido_binario).digest()
    
    except Exception as e:
        raise ValueError(f"Error al calcular el hash del documento: {e}")

def decrypt_private_key(encrypted_sk, password):
        """Descifra la clave privada utilizando AES-256 CBC y verifica la redundancia."""
        try:
            encrypted_data = base64.b64decode(encrypted_sk)  # Decodificar de Base64

            # Extraer SALT (primeros 16 bytes)
            salt = encrypted_data[:16]
            
            # Extraer IV (siguientes 16 bytes)
            iv = encrypted_data[16:32]
            
            # Derivar clave con el salt
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
            
            cipher = AES.new(key, AES.MODE_CBC, iv)  # Crear cifrador AES-CBC

            decrypted_sk = cipher.decrypt(encrypted_data[32:])  # Desencriptar
            decrypted_sk = decrypted_sk[:-decrypted_sk[-1]]  # Eliminar padding PKCS7

            # Verificar redundancia (últimos 50 bits = 7 bytes deben repetirse al final)
            if decrypted_sk[-7:] != decrypted_sk[-14:-7]:
                raise ValueError("Contraseña incorrecta: No se validó la redundancia.")

            return decrypted_sk[:-7]  # Devolver clave privada sin redundancia

        except Exception:
            return None  # Error → Contraseña incorrecta    
    
def detect_active_pdf():
    """Detecta automáticamente el PDF activo incluso cuando esta app está en primer plano"""
    try:
        log_message("firmaApp.log","Intentando detectar el PDF activo...")
        
        if sys.platform == "win32":
            try:
                import psutil
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
    
def enviar_alerta_certificado(nombre, dni):
    """Muestra una alerta simple en la consola cuando hay intentos fallidos."""
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message("firmaApp.log",f"[{timestamp}] ALERTA: Intentos fallidos para {nombre} ({dni})")
    log_message("firmaApp.log","-" * 50)
    
    return True

def register_protocol_handler():
    try:
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
    
def verificar_certificado(cert_data, base_dir):
    """Verifica la validez de un certificado (SPHINCS+ o Dilithium)."""
    try:
        # Detectar algoritmo del certificado
        algoritmo = cert_data.get("algoritmo")  # Por defecto SPHINCS+ para compatibilidad
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
        ent_pk_cert = bytes.fromhex(cert_data["entity_public_key"])  # Clave pública dentro del certificado
        pk_entidad_path = os.path.join(base_dir, "pk_entidad.json")

        if not os.path.exists(pk_entidad_path):
            raise ValueError("No se encontró el archivo de claves públicas de la entidad.")

        # Leer el archivo de claves públicas de la entidad (ahora contiene una lista de objetos)
        with open(pk_entidad_path, "r") as pk_file:
            pk_data_list = json.load(pk_file)
            
            # Verificar que el archivo contiene datos
            if not pk_data_list or not isinstance(pk_data_list, list):
                raise ValueError("El archivo de claves públicas está vacío o no tiene el formato esperado.")
            
            # Filtrar las claves que coinciden con el algoritmo del certificado
            algoritmo_lower = algoritmo.lower()
            claves_algoritmo = [pk for pk in pk_data_list if pk.get("algoritmo", "").lower() == algoritmo_lower]
            
            if not claves_algoritmo:
                raise ValueError(f"No se encontraron claves públicas para el algoritmo {algoritmo}.")
            
            # Comprobar si la clave del certificado coincide con alguna de las claves almacenadas
            clave_encontrada = False
            for pk_entry in claves_algoritmo:
                try:
                    ent_pk_candidata = bytes.fromhex(pk_entry.get("clave", ""))
                    if ent_pk_cert == ent_pk_candidata:
                        clave_encontrada = True
                        log_message("firmaApp.log",f"Clave pública de entidad verificada: {pk_entry.get('titulo', 'Sin título')}")
                        break
                except Exception as e:
                    log_message("firmaApp.log",f"Error al procesar clave candidata: {e}")
            
            if not clave_encontrada:
                raise ValueError("La clave pública de la entidad en el certificado no coincide con ninguna clave oficial.")
            
        # -------------------- VALIDACIÓN FIRMA --------------------
        recalculated_hash_firma = calcular_hash_firma(cert_copy)

        # Convertir la firma a bytes
        firma_bytes = bytes.fromhex(firma)
        
        # Verificar firma según el algoritmo usado
        firma_valida = verificar_firma(recalculated_hash_firma, ent_pk_cert, firma_bytes, algoritmo)


        if not firma_valida:
            raise ValueError("La firma del certificado no es válida.")

        return True
    except Exception as e:
        log_message("firmaApp.log",f"Error al verificar certificado: {e}")
        return False
    
def add_metadata_to_pdf(pdf_path, firma, cert_data, visual_signature_hash=None):
    """Añade la firma y el certificado de autenticación a los metadatos del PDF preservando firmas anteriores."""
    try:
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
            nueva_firma["hash_visual_signature"] = visual_signature_hash.hex()
        
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

def process_uri(uri):
    """Extrae la ruta del PDF desde una URI autofirma:// y verifica el documento"""
    try:
        log_message("firmaApp.log", f"Procesando URI: {uri}")
        
        # Validar formato de la URI
        if not uri.startswith("autofirma://"):
            log_message("firmaApp.log", "El formato de la URI no es válido.")
            return False, None, None, None
        
        # Extraer la ruta codificada
        encoded_path = uri[len("autofirma://"):].rstrip('/')
        
        # Obtener la ruta del archivo
        file_path = None
        
        # Caso especial: detectar PDF activo
        if encoded_path.upper() == "CURRENT_PDF":
            file_path = detect_active_pdf()
            if not file_path:
                log_message("firmaApp.log", "No se pudo detectar automáticamente el PDF activo.")
                return False, None, None, None
            log_message("firmaApp.log", f"PDF activo detectado: {file_path}")
        
        # Caso normal: decodificar ruta
        else:
            try:
                import base64
                file_path = base64.urlsafe_b64decode(encoded_path.encode()).decode()
            except Exception:
                log_message("firmaApp.log", "No se pudo decodificar la ruta del PDF.")
                return False, None, None, None
        
        # Verificar existencia del archivo
        if not os.path.exists(file_path):
            log_message("firmaApp.log", f"No se encuentra el archivo: {file_path}")
            return False, None, None, None
        
        # Extraer metadatos y firmas
        doc = fitz.open(file_path)
        metadata = doc.metadata
        doc.close()
        
        meta_data = json.loads(metadata.get("keywords", "{}"))
        firmas = meta_data.get("firmas", [])
        
        # Verificar que existan firmas
        if not firmas:
            log_message("firmaApp.log", "No se encontraron firmas en el documento.")
            return False, None, None, None
        
        # Calcular hash y retornar resultados
        hash_documento_actual = calcular_hash_documento(file_path)
        return True, file_path, firmas, hash_documento_actual
        
    except Exception as e:
        log_message("firmaApp.log", f"Error al verificar desde URI: {e}")
        return False, None, None, None
    
def verificar_firmas_cascada(firmas, hash_actual, base_dir):  
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
        
        # Verificar certificado
        cert_valido = verificar_certificado(cert_data, base_dir)
        
        # Verificar firma usando el hash actual
        firma_valida = verificar_firma(hash_actual, user_pk, firma, algoritmo)
        
        # Guardar el resultado
        resultados_validacion.append({
            "indice": i,
            "firma_valida": firma_valida,
            "cert_valido": cert_valido,
            "hash_verificacion": hash_actual,
            "firma_data": firma_data
        })
        
        # Calcular el siguiente hash para la cascada si hay más firmas para verificar
        if i > 0 and "hash_visual_signature" in firma_data:
            hash_visual = bytes.fromhex(firma_data["hash_visual_signature"])
            # Operación "resta" conceptual para obtener el hash anterior
            hash_actual = bytes(a ^ b for a, b in zip(hash_actual, hash_visual))
            log_message("firmaApp.log",f"Hash calculado para firma {i}: {hash_actual.hex()[:10]}...")

    resultados_validacion.reverse()
    return resultados_validacion

def verificar_firma(hash_data, clave_pública, firma, algoritmo):
    from package.sphincs import Sphincs
    # Firmar según el algoritmo seleccionado
    if algoritmo.lower() == "sphincs":
        sphincs = Sphincs()
        firma = sphincs.verify(hash_data, firma, clave_pública)
    elif algoritmo.lower() == "dilithium":
        from dilithium_py.ml_dsa import ML_DSA_65  # Usamos ML_DSA_65 (Dilithium3)
        firma = ML_DSA_65.verify(clave_pública, hash_data, firma)
    else:
        return None
    return firma