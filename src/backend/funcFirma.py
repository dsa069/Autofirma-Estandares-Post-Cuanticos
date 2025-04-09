import base64
from datetime import datetime, timedelta
import hashlib
import os
import sys
import fitz  # PyMuPDF
from Crypto.Cipher import AES
from src.backend.funcComunes import log_message

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