import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk  # type: ignore
from backend.funcComunes import log_message, init_paths
from frontend.compComunes import center_window, set_app_instance, set_base_dir, setup_app_icons, crear_vista_nueva, create_button
from frontend.compEntGen import set_app_instance_entidad

BASE_DIR = init_paths()

class CertificadoDigitalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Generador de Certificados SafeInQ")
        self.root.geometry("700x584")
        self.root.resizable(False, False)
        self.root.configure(bg="#F5F5F5")
        center_window(self.root)
        setup_app_icons(self.root, "AlterDiego")

        self.vista_inicial_entidad_generadora()

    def vista_inicial_entidad_generadora(self):
        from frontend.compComunes import create_text
        from frontend.compEntGen import  create_key_list

        vista = crear_vista_nueva(self.root)

        bienvenida_label = create_text(
            vista, text="Bienvenido a Generador de Certificados SafeInQ"
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
        
        lista_frame = create_key_list(vista)
        lista_frame.pack(padx=10, pady=10) 

    def vista_generacion_claves(self):
        """Genera nuevas claves de entidad con parámetros personalizados."""
        try:
            from backend.funcEntGen import generar_claves_entidad, verificar_campos_generacion_claves
            from frontend.compComunes import create_text_field_with_title
            from frontend.compEntGen import create_dropdown_with_text

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
                mensaje, fecha_expedicion, fecha_caducidad = verificar_campos_generacion_claves(titulo, fecha_ini_str, fecha_cad_str, algoritmo)
                if not fecha_expedicion or not fecha_caducidad:
                    messagebox.showerror("Error", mensaje)
                    return

                try:
                    import os
                    id = generar_claves_entidad(
                        titulo, 
                        algoritmo, 
                        fecha_expedicion, 
                        fecha_caducidad, 
                        os.path.join(BASE_DIR, "sk_entidad.json"), 
                        os.path.join(BASE_DIR, "pk_entidad.json"),
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
                    
                    self.vista_inicial_entidad_generadora()
                    
                except Exception as e:
                    messagebox.showerror("Error", f"Error al generar claves: {str(e)}")
                    log_message("entGenApp.log",f"Error al generar claves: {str(e)}")

            botones_frame = ctk.CTkFrame(vista, fg_color="transparent")
            botones_frame.pack(padx=20, pady=10, expand=True)

            volver_btn = create_button(botones_frame, "Cancelar", lambda: self.vista_inicial_entidad_generadora())
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
            from frontend.compComunes import create_text_field, create_text_field_with_title
            from frontend.compEntGen import create_key_row

            vista = crear_vista_nueva(self.root)

            titulo_label = ctk.CTkLabel(vista, text="Generar un certificado Digital", font=("Inter", 25), fg_color="transparent")
            titulo_label.pack(pady=(30, 10))

            datos_frame = ctk.CTkFrame(vista, fg_color="transparent")
            datos_frame.pack(fill="x",padx=40)

            certificado_container = ctk.CTkFrame(datos_frame, fg_color="transparent", height=98)
            certificado_container.pack_propagate(False)
            certificado_container.pack(anchor="w", expand=True, fill ="x")   

            cert_label = ctk.CTkLabel(certificado_container, text="Claves utilizadas para firmar el certificado:",
                                  font=("Inter", 17), text_color="#111111")
            cert_label.pack(anchor="w")

            datos_cert_container = ctk.CTkFrame(
                certificado_container, 
                fg_color="#FFFFFF",
                corner_radius=25,
                border_width=1,
                border_color="#E0E0E0",
                width=620
            )
            datos_cert_container.pack(fill="both", expand=True)

            # Crear un frame intermedio con padding para contener key_row
            padding_frame = ctk.CTkFrame(
                datos_cert_container,
                fg_color="transparent",  # Mismo color que el contenedor padre
                corner_radius=0      # Sin esquinas redondeadas para que sea invisible
            )
            # Usar padding generoso en todos los lados
            padding_frame.pack(pady=(9,0), padx=(1,0))


            key_row = create_key_row(
                lista_frame = padding_frame,
                row_count=0,
                clave=selected_key,
                es_clicable=False,
                separador=False,
                pk_callback_volver_a= lambda: self.vista_crear_certificado(selected_key),
                )

            datos_personales_frame = ctk.CTkFrame(datos_frame, fg_color="transparent")
            datos_personales_frame.pack(fill="x")

            # Crear subframes para cada campo
            titular_container = ctk.CTkFrame(datos_personales_frame, fg_color="transparent")
            titular_container.pack(side="left", fill="x", expand=True, padx=(0, 10))

            dni_container = ctk.CTkFrame(datos_personales_frame, fg_color="transparent")
            dni_container.pack(side="left", fill="x", expand=True, padx=(0, 10))

            titular_field = create_text_field_with_title(titular_container, "Titular del certificado:", "Nombre completo (particular o entidad)", 300)
            dni_field = create_text_field_with_title(dni_container, "Documento identificativo del titular:", "Escriba NIE/NIF/CIF", 300)

            password_container = ctk.CTkFrame(datos_frame, fg_color="transparent")
            password_container.pack(anchor="w") 

            pass_label = ctk.CTkLabel(password_container, text="Establecer contraseña del certificado:",
                                  font=("Inter", 17), text_color="#111111")
            pass_label.pack(anchor="w")

            requisitos_label = ctk.CTkLabel(password_container, text="""La contraseña debe tener:
    - Al menos 8 caracteres
    - Al menos una letra mayúscula
    - Al menos un número
    - Al menos un carácter especial (ej: !@#$%^&*)""",
                font=("Inter", 13), text_color="#111111", justify="left")
            
            requisitos_label.pack(anchor="w", padx=(20, 0), pady = (0,5))

            password_field = create_text_field(password_container, "Escriba la contraseña")
            password_field.configure(show="*")
            password_field.pack(anchor="w")

            pass_confirm_field = create_text_field_with_title(datos_frame, "Confirmar contraseña:", "Escriba la contraseña de nuevo")
            pass_confirm_field.configure(show="*")

            def generate_and_save_certificado():
                nombre = titular_field.get().strip()
                dni = dni_field.get().upper().strip().replace(" ", "").replace("-", "")
                password = password_field.get().strip()
                password_confirm = pass_confirm_field.get().strip()

                valid, msg= validar_datos_usuario(nombre, dni)
                if not valid:
                    messagebox.showerror("Error de validación", msg)
                    log_message("entGenApp.log", f"Error de validación: {msg}")
                    return  
                
                log_message("entGenApp.log",f"Usando clave de entidad: {selected_key['titulo']} ({selected_key["algoritmo"].capitalize()})")

                valid, message = validate_password(password)
                if not valid:
                    messagebox.showerror("Contraseña insegura", message)
                    return
                
                if password != password_confirm:
                    messagebox.showerror("Error de validación", "Las contraseñas no coinciden")
                    log_message("entGenApp.log", "Error: Las contraseñas introducidas no coinciden")
                    return

                try:
                    cert_auth_path, _ = generar_certificado(
                        selected_key,
                        nombre=nombre,
                        dni=dni,
                        password=password
                    )

                    import json
                    with open(cert_auth_path, 'r') as f:
                        cert_data = json.load(f)

                    self.vista_resultado_certificado(cert_data=cert_data)
                except Exception as e:                
                    log_message("entGenApp.log", f"Error generando certificados: {str(e)}")
                    self.vista_resultado_certificado(error=e)

            botones_frame = ctk.CTkFrame(vista, fg_color="transparent")
            botones_frame.pack(padx=20, pady=10, expand=True)

            volver_btn = create_button(botones_frame, "Cancelar", lambda: self.vista_inicial_entidad_generadora())
            volver_btn.pack(side="left", padx=(0, 250))

            guardar_btn = create_button(botones_frame, "Generar", lambda: generate_and_save_certificado())
            guardar_btn.pack(side="left")

        except Exception as e:
            messagebox.showerror("Error", f"Error al generar certificados: {e}")
            log_message("entGenApp.log",f"Error al generar certificados: {e}")            

    def vista_resultado_certificado(self, cert_data = None, error = None):
        """Muestra el resultado de la generación del certificado."""
        from frontend.compComunes import cert_data_list, resize_image_proportionally

        # Crear ventana para mostrar el resultado
        vista = crear_vista_nueva(self.root)

        img = resize_image_proportionally("error" if error else "tick", 100)

        resultado_frame = ctk.CTkFrame(vista, fg_color="#f5f5f5")  # Fondo blanco grisáceo
        resultado_frame.pack(padx=20, pady=20, fill="x")

        # Imagen del check
        label_imagen = ctk.CTkLabel(resultado_frame, image=img, text="", bg_color="#f5f5f5")
        label_imagen.grid(row=0, column=0, padx=(10, 10), pady=10, sticky="w")

        # Texto del mensaje
        label_texto = ctk.CTkLabel(
            resultado_frame,
            text="El certificado se ha generado correctamente" if not error else "La generación del certificado ha fallado",
            font=("Segoe UI", 27),
            text_color="#000000",
            bg_color="#f5f5f5"
        )
        label_texto.grid(row=0, column=1, padx=(5, 10), pady=10, sticky="w")

        if error:
            error_fondo = ctk.CTkFrame(
                vista, 
                fg_color="#FFFFFF",
                corner_radius=25,
                border_width=1,
                border_color="#E0E0E0",
                width=620, 
                height=344
            )
            error_fondo.pack(expand=True, fill="both", padx=20, pady=(10, 0))
            
            # Mostrar el mensaje de error
            error_message = ctk.CTkLabel(
                error_fondo, 
                text=str(error),
                font=("Inter", 16),
                text_color="#CB1616",
                wraplength=610,
                justify="left"
            )
            error_message.pack(pady=(5, 20), padx=20, anchor="w")
        else:

            datos_list = cert_data_list(vista, cert_data)
            datos_list.pack()

        volver_btn = create_button(vista, "Finalizar", lambda: self.vista_inicial_entidad_generadora())
        volver_btn.pack(pady=20)


if __name__ == "__main__":
    root = tk.Tk()
    set_base_dir(BASE_DIR)
    app = CertificadoDigitalApp(root)
    set_app_instance(app)
    set_app_instance_entidad(app)
    root.mainloop()