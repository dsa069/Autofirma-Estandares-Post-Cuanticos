import sys
import os
from backend.funcComunes import log_message, init_paths

BASE_DIR = init_paths()

import tkinter as tk
from tkinter import messagebox, simpledialog
import customtkinter as ctk  # type: ignore
from frontend.compComunes import center_window, crear_vista_nueva, create_base_list, create_base_row, create_button, create_text, create_text_field_with_title, resize_image_proportionally, set_app_instance, setup_app_icons, vista_mostrar_pk
from frontend.compEntGen import create_dropdown_with_text, create_key_list, set_app_instance_entidad

SK_ENTIDAD_PATH = os.path.join(BASE_DIR, "sk_entidad.json")
PK_ENTIDAD_PATH = os.path.join(BASE_DIR, "pk_entidad.json")

class CertificadoDigitalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Generador de Certificados Digitales - Sphincs")
        self.root.geometry("700x584")
        self.root.resizable(False, False)
        self.root.configure(bg="#F5F5F5")
        center_window(self.root)

        # Rutas del icono
        setup_app_icons(self.root, BASE_DIR, "AlterDiego")

        self.vista_inicial()

    def vista_inicial(self):
        # Título

        vista = crear_vista_nueva(self.root)

        bienvenida_label = create_text(
            vista, text="Bienvenido a la aplicación de Generador Certificados Post-Cuánticos"
        )
        bienvenida_label.pack(pady=(30,10), padx=(50, 0))

        introduction_label = create_text(
            vista, text="Esta herramienta te permite generar certificados digitales y claves con criptografía resistentes a ataques cuánticos, garantizando la seguridad a largo plazo. " \
            "La aplicación utiliza estándares avanzados como Dilithium y SPHINCS+. "
            "Para crear un certificado selecciona una clave de entidad existente o genera una nueva. "
        )
        introduction_label.pack(pady=10, padx=(50, 0))

        btn = create_button(vista, "Generar nuevas claves", lambda: self.vista_generacion_claves(), 220)
        btn.pack(pady=12, padx=(60, 0), anchor="w")
        
        lista_frame = create_key_list(vista, BASE_DIR)
        lista_frame.pack(padx=10, pady=10) 

        #txtField = create_text_field_with_title(root, "Vuelva a escribir la contarseña:", "Escriba la contraseña")

        #dropdown_algoritmo = create_dropdown_with_text(root, "Elige el algoritmo de generación de claves:", ["DILITHIUM3", "SPHINCS+ (SHA-256)"], "Seleccione algoritmo" )

    def vista_generacion_claves(self):
        """Genera nuevas claves de entidad con parámetros personalizados."""
        try:
            from backend.funcEntGen import generar_claves_entidad, verificar_campos_generacion_claves

            vista = crear_vista_nueva(self.root)


            # Variables
            titulo_var = tk.StringVar()
            algoritmo_var = tk.StringVar(value="sphincs")
            
            # Variables para las fechas
            fecha_ini_var = tk.StringVar()
            fecha_cad_var = tk.StringVar()
            
            # Establecer fecha por defecto como hoy en formato DD/MM/AAAA
            import datetime
            hoy = datetime.date.today()
            fecha_ini_var.set(hoy.strftime("%d/%m/%Y"))
            
            # Fecha de caducidad por defecto a 2 años
            fecha_cad = hoy + datetime.timedelta(days=2*365)
            fecha_cad_var.set(fecha_cad.strftime("%d/%m/%Y"))

            # Crear formulario
            tk.Label(vista, text="Datos de la Nueva Clave de Entidad", 
                    font=("Arial", 14, "bold")).pack(pady=10)

            # Título/Entidad
            frame_titulo = tk.Frame(vista)
            frame_titulo.pack(fill=tk.X, padx=20, pady=5)
            tk.Label(frame_titulo, text="Nombre de Entidad:", width=15, anchor="w").pack(side=tk.LEFT)
            tk.Entry(frame_titulo, textvariable=titulo_var, width=30).pack(side=tk.LEFT, padx=5)

            # Algoritmo
            frame_algoritmo = tk.Frame(vista)
            frame_algoritmo.pack(fill=tk.X, padx=20, pady=5)
            tk.Label(frame_algoritmo, text="Algoritmo:", width=15, anchor="w").pack(side=tk.LEFT)
            tk.Radiobutton(frame_algoritmo, text="SPHINCS", variable=algoritmo_var, 
                        value="sphincs").pack(side=tk.LEFT)
            tk.Radiobutton(frame_algoritmo, text="Dilithium", variable=algoritmo_var, 
                        value="dilithium").pack(side=tk.LEFT)

            # Fecha de inicio de validez
            frame_fecha_ini = tk.Frame(vista)
            frame_fecha_ini.pack(fill=tk.X, padx=20, pady=5)
            tk.Label(frame_fecha_ini, text="Fecha de inicio:", width=15, anchor="w").pack(side=tk.LEFT)
            tk.Entry(frame_fecha_ini, textvariable=fecha_ini_var, width=15).pack(side=tk.LEFT, padx=5)
            tk.Label(frame_fecha_ini, text="(DD/MM/AAAA)").pack(side=tk.LEFT)
            
            # Fecha de caducidad
            frame_fecha_cad = tk.Frame(vista)
            frame_fecha_cad.pack(fill=tk.X, padx=20, pady=5)
            tk.Label(frame_fecha_cad, text="Fecha caducidad:", width=15, anchor="w").pack(side=tk.LEFT)
            tk.Entry(frame_fecha_cad, textvariable=fecha_cad_var, width=15).pack(side=tk.LEFT, padx=5)
            tk.Label(frame_fecha_cad, text="(DD/MM/AAAA)").pack(side=tk.LEFT)

            def generate_and_save():
                titulo = titulo_var.get().strip()
                algoritmo = algoritmo_var.get()
                fecha_ini_str = fecha_ini_var.get().strip()
                fecha_cad_str = fecha_cad_var.get().strip()

                # Verificar campos usando la nueva función
                mensaje, fecha_expedicion, fecha_caducidad = verificar_campos_generacion_claves(titulo, fecha_ini_str, fecha_cad_str)
                if not fecha_expedicion or not fecha_caducidad:
                    messagebox.showerror("Error", mensaje)
                    return

                try:
                    id = generar_claves_entidad(
                        titulo, 
                        algoritmo, 
                        fecha_expedicion, 
                        fecha_caducidad, 
                        SK_ENTIDAD_PATH, 
                        PK_ENTIDAD_PATH,
                    )
                    
                    if id == -1:
                        raise Exception("Error al generar claves de entidad")
                    
                    log_message("entGenApp.log",f"Nuevas claves generadas: {titulo} ({algoritmo.upper()})")
                    messagebox.showinfo("Éxito", 
                                    f"Nuevas claves de entidad generadas correctamente:\n"
                                    f"id: {id}\n"
                                    f"Entidad: {titulo}\n"
                                    f"Algoritmo: {algoritmo.upper()}\n"
                                    f"Válida desde: {fecha_expedicion}\n"
                                    f"Válida hasta: {fecha_caducidad}")
                    
                    vista.destroy()
                    
                except Exception as e:
                    messagebox.showerror("Error", f"Error al generar claves: {str(e)}")
                    log_message("entGenApp.log",f"Error al generar claves: {str(e)}")

            # Botones
            frame_botones = tk.Frame(vista)
            frame_botones.pack(pady=20)
            tk.Button(frame_botones, text="Generar y Guardar", command=generate_and_save,
                    bg="#4CAF50", fg="white", width=20).pack(side=tk.LEFT, padx=5)
            tk.Button(frame_botones, text="Cancelar", command=vista.destroy,
                    bg="#f44336", fg="white", width=10).pack(side=tk.LEFT, padx=5)
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al abrir ventana de generación de claves: {str(e)}")
            log_message("entGenApp.log",f"Error al abrir ventana de generación de claves: {str(e)}")

    def vista_crear_certificado(self):
        """Genera dos certificados digitales: uno para firma y otro para autenticación."""
        try:
            from backend.funcEntGen import cargar_claves_entidad
            from backend.funcEntGen import generar_certificado, validar_datos_usuario, validate_password
            # Obtener datos del usuario
            nombre = self.name_entry.get().strip()
            # Normalizar el DNI/NIE/CIF (quitar espacios y convertir a mayúsculas)
            dni = self.dni_entry.get().upper().strip().replace(" ", "").replace("-", "")

            valid, msg= validar_datos_usuario(nombre, dni)
            if not valid:
                raise Exception(msg)
            
            
            # Leer todas las claves disponibles
            claves_disponibles = cargar_claves_entidad(SK_ENTIDAD_PATH, PK_ENTIDAD_PATH)
            
            # Verificar si hay claves disponibles
            total_claves = len(claves_disponibles["sphincs"]) + len(claves_disponibles["dilithium"])
            if total_claves == 0:
                messagebox.showerror("Error", "No hay claves de entidad disponibles. Debe generar al menos una.")
                return
            
            # Crear ventana para selección de clave
            key_window = tk.Toplevel(self.root)
            key_window.title("Selección de Clave de Entidad")
            key_window.geometry("500x400")
            key_window.transient(self.root)
            key_window.grab_set()
            
            # Variables para la selección
            selected_key_id = tk.StringVar()
            selected_key = [None]  # Usamos lista para modificarla en función interna
            
            # Título
            tk.Label(key_window, text="Seleccione la clave para firmar el certificado", 
                    font=("Arial", 12, "bold")).pack(pady=10)
            
            # Frame con scroll para las claves
            frame = tk.Frame(key_window)
            frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Scrollbar y canvas
            scrollbar = tk.Scrollbar(frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            canvas = tk.Canvas(frame, yscrollcommand=scrollbar.set)
            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            scrollbar.config(command=canvas.yview)
            
            # Frame interior para contenido
            interior = tk.Frame(canvas)
            canvas.create_window((0, 0), window=interior, anchor=tk.NW)
            interior.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            
            # Agregar claves por algoritmo
            found_keys = False
            
            # Depuración: imprimir claves disponibles
            log_message("entGenApp.log",f"\n--- ANÁLISIS DE CLAVES RECUPERADAS PARA UI ---")
            log_message("entGenApp.log",f"Claves SPHINCS: {len(claves_disponibles['sphincs'])}")
            log_message("entGenApp.log",f"Claves Dilithium: {len(claves_disponibles['dilithium'])}")
            
            for algoritmo in ["sphincs", "dilithium"]:
                log_message("entGenApp.log",f"\nProcesando bloque de claves {algoritmo.upper()}")
                if not claves_disponibles[algoritmo]:
                    log_message("entGenApp.log",f"  No hay claves disponibles para {algoritmo}")
                    continue
                    
                # Título del algoritmo
                tk.Label(interior, text=f"Claves {algoritmo.upper()}", 
                        font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(10, 5))
                
                for idx, key in enumerate(claves_disponibles[algoritmo]):
                    log_message("entGenApp.log",f"  Agregando clave {idx+1}: {key['titulo']} (ID: {key['id']})")
                    found_keys = True
                    
                    # Frame para esta clave
                    key_frame = tk.Frame(interior, relief=tk.RIDGE, bd=1)
                    key_frame.pack(fill=tk.X, pady=5, padx=5)
                    
                    # Color según vigencia
                    bg_color = "#e8f5e9" if key["vigente"] else "#ffebee"
                    key_frame.configure(bg=bg_color)
                    
                    # Radiobutton para selección
                    rb = tk.Radiobutton(key_frame, variable=selected_key_id, 
                                    value=f"{algoritmo}:{key['id']}", bg=bg_color)
                    rb.pack(side=tk.LEFT, padx=5)
                    
                    # Panel de información
                    info_frame = tk.Frame(key_frame, bg=bg_color)
                    info_frame.pack(fill=tk.X, expand=True, padx=5)
                    
                    # Título y estado
                    estado = "Vigente" if key["vigente"] else "Caducada"
                    titulo_label = tk.Label(info_frame, 
                                        text=f"{key['titulo']} - {estado}", 
                                        font=("Arial", 10, "bold"),
                                        fg="#388e3c" if key["vigente"] else "#d32f2f",
                                        bg=bg_color)
                    titulo_label.pack(anchor=tk.W)
                    
                    # Fechas formateadas
                    try:
                        import datetime
                        fecha_exp = datetime.date.fromisoformat(key["fecha_expedicion"]).strftime("%d/%m/%Y")
                        fecha_cad = datetime.date.fromisoformat(key["fecha_caducidad"]).strftime("%d/%m/%Y")
                        fechas_text = f"Válida: {fecha_exp} - {fecha_cad}"
                    except:
                        fechas_text = "Fechas no disponibles"
                    
                    fechas_label = tk.Label(info_frame, text=fechas_text, bg=bg_color)
                    fechas_label.pack(anchor=tk.W)
            
            # IMPORTANTE: Todo lo siguiente debe estar FUERA del bucle for
            if not found_keys:
                tk.Label(interior, text="No hay claves disponibles.", 
                        font=("Arial", 10, "italic"), fg="#d32f2f").pack(pady=20)
            else:
                # Seleccionar primera clave por defecto
                first_algo = "sphincs" if claves_disponibles["sphincs"] else "dilithium"
                if claves_disponibles[first_algo]:
                    first_key = claves_disponibles[first_algo][0]
                    selected_key_id.set(f"{first_algo}:{first_key['id']}")

            # Variable para confirmar selección
            selection_confirmed = [False]
            
            def confirm_selection():
                key_id = selected_key_id.get()
                if not key_id:
                    messagebox.showerror("Error", "Debe seleccionar una clave de entidad")
                    return
                
                # Extraer algoritmo e ID
                algoritmo, id_clave = key_id.split(":")
                
                # Buscar clave seleccionada
                for key in claves_disponibles[algoritmo]:
                    if key["id"] == id_clave:
                        selected_key[0] = key
                        break
                
                if not selected_key[0]:
                    messagebox.showerror("Error", "Clave no encontrada")
                    return
                
                # Advertir si está caducada
                if not selected_key[0]["vigente"]:
                    if not messagebox.askyesno("Advertencia", 
                                            "La clave seleccionada está caducada. ¿Desea continuar?"):
                        return
                
                selection_confirmed[0] = True
                key_window.destroy()
            
            # IMPORTANTE: Los botones deben estar FUERA de confirm_selection
            button_frame = tk.Frame(key_window)
            button_frame.pack(pady=10)
            
            tk.Button(button_frame, text="Usar clave seleccionada", command=confirm_selection,
                    bg="#0078D4", fg="white", width=20).pack(side=tk.LEFT, padx=5)
            
            tk.Button(button_frame, text="Cancelar", command=key_window.destroy,
                    width=10).pack(side=tk.LEFT, padx=5)
            
            # Esperar a que se cierre la ventana
            self.root.wait_window(key_window)
            
            # Verificar si se confirmó la selección
            if not selection_confirmed[0] or not selected_key[0]:
                return
            
            # -----------------------Usar la clave seleccionada----------------------------
            clave_seleccionada = selected_key[0]
            
            log_message("entGenApp.log",f"Usando clave de entidad: {clave_seleccionada['titulo']} ({clave_seleccionada["algoritmo"].capitalize()})")
            
            # Solicitar contraseña de cifrado al usuario con validación
            password = None
            while password is None:
                password = simpledialog.askstring("Contraseña", 
                                                "Introduce una contraseña para cifrar la clave privada:\n\n"
                                                "La contraseña debe tener:\n"
                                                "- Al menos 8 caracteres\n"
                                                "- Al menos una letra mayúscula\n"
                                                "- Al menos un número\n"
                                                "- Al menos un carácter especial (ej: !@#$%^&*)", 
                                                show="*")
                
                if password is None:  # Usuario canceló el diálogo
                    return
                
                valid, message = validate_password(password)
                if not valid:
                    messagebox.showerror("Contraseña insegura", message)
                    password = None

            cert_auth_path, cert_sign_path = generar_certificado(
                clave_seleccionada,
                nombre=nombre,
                dni=dni,
                password=password
            )
            
            messagebox.showinfo("Éxito", 
                            f"Certificados generados con {algoritmo} con éxito:\n{cert_auth_path}\n{cert_sign_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar certificados: {e}")
            log_message("entGenApp.log",f"Error al generar certificados: {e}")            

    def vista_resultado_certificado(self, resultado):
        """Muestra el resultado de la generación del certificado."""
        # Crear ventana para mostrar el resultado
        vista = crear_vista_nueva(self.root)


if __name__ == "__main__":
    root = tk.Tk()
    app = CertificadoDigitalApp(root)
    set_app_instance(app)
    set_app_instance_entidad(app)
    root.mainloop()