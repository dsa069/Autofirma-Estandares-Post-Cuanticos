import sys
import os
from backend.funcComunes import log_message, init_paths

BASE_DIR = init_paths()

import tkinter as tk
from tkinter import messagebox, simpledialog
import customtkinter as ctk  # type: ignore
from frontend.compComunes import center_window, crear_vista_nueva, create_base_list, create_base_row, create_button, create_text, create_text_field, create_text_field_with_title, resize_image_proportionally, set_app_instance, setup_app_icons, vista_mostrar_pk
from frontend.compEntGen import create_dropdown_with_text, create_key_list, create_key_row, set_app_instance_entidad

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

        #dropdown_algoritmo = create_dropdown_with_text(root, "Elige el algoritmo de generación de claves:", ["DILITHIUM3", "SPHINCS+ (SHA-256)"], "Seleccione algoritmo" )

    def vista_generacion_claves(self):
        """Genera nuevas claves de entidad con parámetros personalizados."""
        try:
            from backend.funcEntGen import generar_claves_entidad, verificar_campos_generacion_claves

            vista = crear_vista_nueva(self.root)

            titulo_label = ctk.CTkLabel(vista, text="Generar un par de claves", font=("Inter", 25), fg_color="transparent")
            titulo_label.pack(pady=40)

            datos_frame = ctk.CTkFrame(vista, fg_color="transparent")
            datos_frame.pack(fill="x",padx=40)

            tiutlo_field = create_text_field_with_title(datos_frame, "Establezca un título representativo para las claves:", "Escriba el título")

            # Crear un frame para las fechas
            fechas_frame = ctk.CTkFrame(datos_frame, fg_color="transparent")
            fechas_frame.pack(fill="x", pady=30)

            # Crear subframes para cada campo
            fecha_exp_container = ctk.CTkFrame(fechas_frame, fg_color="transparent")
            fecha_exp_container.pack(side="left", fill="x", expand=True, padx=(0, 10))

            fecha_cad_container = ctk.CTkFrame(fechas_frame, fg_color="transparent")
            fecha_cad_container.pack(side="left", fill="x", expand=True, padx=(0, 10))

            fecha_exp_field = create_text_field_with_title(fecha_exp_container, "Fecha de inicio:", "dd/mm/aaaa", 300)
            fecha_cad_field = create_text_field_with_title(fecha_cad_container, "Fecha de caducidad:", "dd/mm/aaaa", 300)

            algoritmo_drop = create_dropdown_with_text(datos_frame, "Seleccione el algoritmo de generación de claves:", ["SPHINCS", "DILITHIUM"], "Seleccione algoritmo" )
            
            # Establecer fecha por defecto como hoy en formato DD/MM/AAAA
            import datetime
            hoy = datetime.date.today()
            fecha_exp_field.insert(0, hoy.strftime("%d/%m/%Y"))
            
            # Fecha de caducidad por defecto a 2 años
            fecha_cad = hoy + datetime.timedelta(days=2*365)
            fecha_cad_field.insert(0, fecha_cad.strftime("%d/%m/%Y"))

            def generate_and_save():
                titulo = tiutlo_field.get().strip()
                algoritmo = algoritmo_drop.get()
                fecha_ini_str = fecha_exp_field.get().strip()
                fecha_cad_str = fecha_cad_field.get().strip()

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
                    
                    self.vista_inicial()
                    
                except Exception as e:
                    messagebox.showerror("Error", f"Error al generar claves: {str(e)}")
                    log_message("entGenApp.log",f"Error al generar claves: {str(e)}")

            botones_frame = ctk.CTkFrame(vista, fg_color="transparent")
            botones_frame.pack(padx=20, pady=10, expand=True)

            volver_btn = create_button(botones_frame, "Cancelar", lambda: self.vista_inicial())
            volver_btn.pack(side="left", padx=(0, 250))

            guardar_btn = create_button(botones_frame, "Generar", lambda: generate_and_save())
            guardar_btn.pack(side="left")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al abrir ventana de generación de claves: {str(e)}")
            log_message("entGenApp.log",f"Error al abrir ventana de generación de claves: {str(e)}")

    def vista_crear_certificado(self, selected_key):
        """Genera dos certificados digitales: uno para firma y otro para autenticación."""
        try:
            from backend.funcEntGen import generar_certificado, validar_datos_usuario, validate_password
            
            vista = crear_vista_nueva(self.root)

            titulo_label = ctk.CTkLabel(vista, text="Generar un certificado Digital", font=("Inter", 25), fg_color="transparent")
            titulo_label.pack(pady=(30, 10))

            datos_frame = ctk.CTkFrame(vista, fg_color="transparent")
            datos_frame.pack(fill="x",padx=40)

            certificado_container = ctk.CTkFrame(datos_frame, fg_color="transparent")
            certificado_container.pack(anchor="w", pady=(10, 10))

            cert_label = ctk.CTkLabel(certificado_container, text="Claves utilizadas para firmar el certificado:",
                                  font=("Inter", 17), text_color="#111111")
            cert_label.pack(anchor="w")

            datos_cert_container = ctk.CTkFrame(
                certificado_container, 
                fg_color="#FFFFFF",
                corner_radius=25,
                border_width=0,
                border_color="#E0E0E0",
                width=620, 
                height=100
            )
            datos_cert_container.pack_propagate(False)

            key_row = create_key_row(
                lista_frame = datos_cert_container,
                base_dir=BASE_DIR,
                row_count=0,
                clave=selected_key
                )
            
            for widget in datos_cert_container.winfo_children():
                if isinstance(widget, tk.Frame) and widget.winfo_height() == 1:
                    # Verificar si el widget usa grid y tiene información de fila
                    grid_info = widget.grid_info()
                    if grid_info and 'row' in grid_info:
                        if int(grid_info["row"]) == 1:
                            widget.destroy()
                            break

            datos_cert_container.pack()

            datos_personales_frame = ctk.CTkFrame(datos_frame, fg_color="transparent")
            datos_personales_frame.pack(fill="x")

            # Crear subframes para cada campo
            titular_container = ctk.CTkFrame(datos_personales_frame, fg_color="transparent")
            titular_container.pack(side="left", fill="x", expand=True, padx=(0, 10))

            dni_container = ctk.CTkFrame(datos_personales_frame, fg_color="transparent")
            dni_container.pack(side="left", fill="x", expand=True, padx=(0, 10))

            titular_field = create_text_field_with_title(titular_container, "Titular del certificado:", "Escriba el nombre completo del particular o entidad", 300)
            dni_field = create_text_field_with_title(dni_container, "Dcomuneto identificativo del titular:", "Escriba el documento identificativo del particular o entidad", 300)

            password_container = ctk.CTkFrame(datos_frame, fg_color="transparent")
            password_container.pack(anchor="w", pady=(10, 10)) 

            pass_label = ctk.CTkLabel(password_container, text="Establecer contraseña del certificado:",
                                  font=("Inter", 17), text_color="#111111")
            pass_label.pack(anchor="w")

            requisitos_label = ctk.CTkLabel(password_container, text="""La contraseña debe tener:
                - Al menos 8 caracteres
                - Al menos una letra mayúscula
                - Al menos un número
                - Al menos un carácter especial (ej: !@#$%^&*)""",
                font=("Inter", 13), text_color="#111111", justify="left")
            
            requisitos_label.pack(anchor="w", padx=(20, 0), pady=10)

            password_field = create_text_field(password_container, "Escriba la contraseña")
            password_field.pack(anchor="w")

            pass_confirm_field = create_text_field_with_title(datos_frame, "Confirmar contraseña:", "Escriba la contraseña de nuevo")
            
            def generate_and_save_certificado():
                nombre = titular_field.get().strip()
                dni = dni_field.get().upper().strip().replace(" ", "").replace("-", "")
                password = password_field.get().strip()

                valid, msg= validar_datos_usuario(nombre, dni)
                if not valid:
                    raise Exception(msg)
                # -----------------------Usar la clave seleccionada----------------------------
                clave_seleccionada = selected_key[0]
                
                log_message("entGenApp.log",f"Usando clave de entidad: {clave_seleccionada['titulo']} ({clave_seleccionada["algoritmo"].capitalize()})")
                
                # Solicitar contraseña de cifrado al usuario con validación
                
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
                                f"Certificados generados con {selected_key[algoritmo]} con éxito:\n{cert_auth_path}\n{cert_sign_path}")
        
            botones_frame = ctk.CTkFrame(vista, fg_color="transparent")
            botones_frame.pack(padx=20, pady=10, expand=True)

            volver_btn = create_button(botones_frame, "Cancelar", lambda: self.vista_inicial())
            volver_btn.pack(side="left", padx=(0, 250))

            guardar_btn = create_button(botones_frame, "Generar", lambda: generate_and_save_certificado())
            guardar_btn.pack(side="left")

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