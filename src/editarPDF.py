import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import fitz  # PyMuPDF
import json
import os
from datetime import datetime, timedelta

class PDFModifierApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF y Firma Modificador")
        self.root.geometry("500x400")
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Modificador de PDF y Firmas", 
                               font=("Helvetica", 14, "bold"))
        title_label.pack(pady=10)
        
        # Description
        desc_label = ttk.Label(main_frame, text="Seleccione una operación para modificar un PDF:", 
                              wraplength=450)
        desc_label.pack(pady=5)
        
        # Create buttons with descriptive frames
        btn_frame1 = ttk.LabelFrame(main_frame, text="Opción 1")
        btn_frame1.pack(fill=tk.X, pady=5)
        btn_change_word = ttk.Button(btn_frame1, text="Cambiar primera palabra a 'babayaga'",
                                   command=self.change_first_word)
        btn_change_word.pack(fill=tk.X, padx=10, pady=5)
        
        btn_frame2 = ttk.LabelFrame(main_frame, text="Opción 2")
        btn_frame2.pack(fill=tk.X, pady=5)
        btn_modify_signature = ttk.Button(btn_frame2, text="Modificar tercer carácter de la firma por 'c'",
                                       command=self.modify_signature)
        btn_modify_signature.pack(fill=tk.X, padx=10, pady=5)
        
        btn_frame3 = ttk.LabelFrame(main_frame, text="Opción 3")
        btn_frame3.pack(fill=tk.X, pady=5)
        btn_modify_pubkey = ttk.Button(btn_frame3, text="Modificar quinto carácter de entity_public_key por 'c'",
                                     command=self.modify_pubkey)
        btn_modify_pubkey.pack(fill=tk.X, padx=10, pady=5)
        
        btn_frame4 = ttk.LabelFrame(main_frame, text="Opción 4")
        btn_frame4.pack(fill=tk.X, pady=5)
        btn_modify_date = ttk.Button(btn_frame4, text="Añadir un día a la fecha de firma",
                                command=self.modify_signature_date)
        btn_modify_date.pack(fill=tk.X, padx=10, pady=5)

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Listo")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=10)
        
    def change_first_word(self):
        """Change the first word of a PDF to 'babayaga'"""
        self.status_var.set("Seleccionando PDF...")
        
        try:
            # Open file dialog to select PDF
            file_path = filedialog.askopenfilename(
                title="Seleccionar PDF para modificar",
                filetypes=[("Archivos PDF", "*.pdf"), ("Todos los archivos", "*.*")]
            )
            
            if not file_path:
                self.status_var.set("Operación cancelada")
                return
                
            # Open the PDF
            doc = fitz.open(file_path)
            
            # Find and replace the first word
            word_found = False
            for page_num in range(len(doc)):
                page = doc[page_num]
                words = page.get_text("words")  # List of (x0, y0, x1, y1, word, block_no, line_no, word_no)
                
                if words:
                    # First word found
                    first_word = words[0]
                    rect = fitz.Rect(first_word[0], first_word[1], first_word[2], first_word[3])
                    
                    # Redact the first word
                    annot = page.add_redact_annot(rect)
                    page.apply_redactions()
                    
                    # Insert the new text
                    page.insert_text(rect.tl, "babayaga", fontsize=12)
                    word_found = True
                    self.status_var.set(f"Palabra reemplazada: '{first_word[4]}' → 'babayaga'")
                    break
            
            if not word_found:
                messagebox.showinfo("Información", "No se encontraron palabras en el documento")
                doc.close()
                self.status_var.set("No se encontraron palabras")
                return
                
            # Save the modified PDF
            save_path = filedialog.asksaveasfilename(
                title="Guardar PDF modificado",
                defaultextension=".pdf",
                filetypes=[("Archivos PDF", "*.pdf")],
                initialfile="babayaga_" + os.path.basename(file_path)
            )
            
            if save_path:
                doc.save(save_path)
                messagebox.showinfo("Éxito", f"Archivo modificado guardado en:\n{save_path}")
                self.status_var.set(f"PDF guardado en: {save_path}")
            else:
                self.status_var.set("Guardado cancelado")
            
            doc.close()
            
        except Exception as e:
            messagebox.showerror("Error", f"Se produjo un error: {str(e)}")
            self.status_var.set(f"Error: {str(e)}")
    
    def modify_signature(self):
        """Modify the third character of the signature in the PDF metadata"""
        self.status_var.set("Seleccionando PDF firmado...")
        
        try:
            # Open file dialog to select signed PDF
            file_path = filedialog.askopenfilename(
                title="Seleccionar PDF firmado",
                filetypes=[("Archivos PDF", "*.pdf"), ("Todos los archivos", "*.*")]
            )
            
            if not file_path:
                self.status_var.set("Operación cancelada")
                return
            
            # First, make a copy of the original file that we'll modify
            save_path = filedialog.asksaveasfilename(
                title="Guardar PDF con firma modificada",
                defaultextension=".pdf",
                filetypes=[("Archivos PDF", "*.pdf")],
                initialfile="firma_mod_" + os.path.basename(file_path)
            )
            
            if not save_path:
                self.status_var.set("Guardado cancelado")
                return
                
            # Copy the original file to the new location
            with open(file_path, "rb") as src_file:
                with open(save_path, "wb") as dst_file:
                    dst_file.write(src_file.read())
            
            # Now open the new file for modification
            doc = fitz.open(save_path)
            metadata = doc.metadata
            
            if "keywords" not in metadata:
                messagebox.showerror("Error", "El PDF no contiene metadatos de firma")
                self.status_var.set("El PDF no contiene metadatos de firma")
                doc.close()
                return
                
            try:
                # Parse metadata
                meta_data = json.loads(metadata.get("keywords", "{}"))
                
                # Verificar si hay múltiples firmas
                if "firmas" in meta_data and meta_data["firmas"]:
                    # Formato nuevo con múltiples firmas
                    firmas = meta_data["firmas"]
                    
                    # Si hay más de una firma, preguntar si modificar todas o solo la primera
                    modify_all = False
                    if len(firmas) > 1:
                        result = messagebox.askyesno(
                            "Múltiples firmas", 
                            f"El documento contiene {len(firmas)} firmas. ¿Desea modificar TODAS las firmas?\n\n"
                            "Seleccione 'No' para modificar solo la primera firma."
                        )
                        modify_all = result
                    
                    # Contador para número de firmas modificadas
                    modified_count = 0
                    
                    # Modificar las firmas según la elección
                    if modify_all:
                        # Modificar todas las firmas
                        for i in range(len(firmas)):
                            firma = firmas[i]["firma"]
                            if len(firma) > 2:
                                original_char = firma[2]
                                new_char = 'd' if original_char == 'c' else 'c'
                                firmas[i]["firma"] = firma[:2] + new_char + firma[3:]
                                modified_count += 1
                    else:
                        # Modificar solo la primera firma
                        firma = firmas[0]["firma"]
                        if len(firma) > 2:
                            original_char = firma[2]
                            new_char = 'd' if original_char == 'c' else 'c'
                            firmas[0]["firma"] = firma[:2] + new_char + firma[3:]
                            modified_count = 1
                    
                    # Actualizar los metadatos solo si se modificó alguna firma
                    if modified_count > 0:
                        # Update metadata
                        metadata["keywords"] = json.dumps(meta_data, separators=(',', ':'))
                        doc.set_metadata(metadata)
                        
                        # Save the modified PDF
                        doc.save(save_path, incremental=True, encryption=0)
                        
                        # Mensaje de éxito
                        if modify_all:
                            messagebox.showinfo("Éxito", f"Se han modificado {modified_count} firma(s).")
                        else:
                            messagebox.showinfo("Éxito", "Se ha modificado la primera firma.")
                        
                        self.status_var.set(f"PDF con firma(s) modificada(s) guardado en: {save_path}")
                    else:
                        messagebox.showinfo("Información", "No se ha modificado ninguna firma.")
                        self.status_var.set("No se ha modificado ninguna firma")
                    
                    doc.close()
                    
                elif "firma" in meta_data:
                    # Formato antiguo con una sola firma
                    firma = meta_data["firma"]
                    if len(firma) > 2:
                        original_char = firma[2]
                        new_char = 'd' if original_char == 'c' else 'c'
                        meta_data["firma"] = firma[:2] + new_char + firma[3:]
                        
                        # Update metadata
                        metadata["keywords"] = json.dumps(meta_data, separators=(',', ':'))
                        doc.set_metadata(metadata)
                        
                        # Save the modified PDF
                        doc.save(save_path, incremental=True, encryption=0)
                        
                        messagebox.showinfo("Éxito", f"Firma modificada. Tercer carácter cambiado de '{original_char}' a '{new_char}'")
                        self.status_var.set(f"PDF con firma modificada guardado en: {save_path}")
                    else:
                        messagebox.showwarning("Advertencia", "La firma es demasiado corta para modificar el tercer carácter")
                        self.status_var.set("La firma es demasiado corta")
                    
                    doc.close()
                else:
                    messagebox.showerror("Error", "El PDF no contiene firmas en los metadatos")
                    self.status_var.set("El PDF no contiene firmas en los metadatos")
                    doc.close()
                    return
            
            except json.JSONDecodeError:
                messagebox.showerror("Error", "Los metadatos no están en formato JSON válido")
                self.status_var.set("Error: Formato de metadatos inválido")
                doc.close()
            
        except Exception as e:
            messagebox.showerror("Error", f"Se produjo un error: {str(e)}")
            self.status_var.set(f"Error: {str(e)}")

    def modify_pubkey(self):
        """Modify the fifth character of the entity_public_key in the certificate"""
        self.status_var.set("Seleccionando PDF firmado...")
        
        try:
            # Open file dialog to select signed PDF
            file_path = filedialog.askopenfilename(
                title="Seleccionar PDF firmado",
                filetypes=[("Archivos PDF", "*.pdf"), ("Todos los archivos", "*.*")]
            )
            
            if not file_path:
                self.status_var.set("Operación cancelada")
                return
            
            # First, make a copy of the original file that we'll modify
            save_path = filedialog.asksaveasfilename(
                title="Guardar PDF con certificado modificado",
                defaultextension=".pdf",
                filetypes=[("Archivos PDF", "*.pdf")],
                initialfile="cert_mod_" + os.path.basename(file_path)
            )
            
            if not save_path:
                self.status_var.set("Guardado cancelado")
                return
                
            # Copy the original file to the new location
            with open(file_path, "rb") as src_file:
                with open(save_path, "wb") as dst_file:
                    dst_file.write(src_file.read())
            
            # Now open the new file for modification
            doc = fitz.open(save_path)
            metadata = doc.metadata
            
            if "keywords" not in metadata:
                messagebox.showerror("Error", "El PDF no contiene metadatos de firma")
                self.status_var.set("El PDF no contiene metadatos de firma")
                doc.close()
                return
                
            try:
                # Parse metadata
                meta_data = json.loads(metadata.get("keywords", "{}"))
                
                # Verificar si hay múltiples firmas
                if "firmas" in meta_data and meta_data["firmas"]:
                    # Formato nuevo con múltiples firmas
                    firmas = meta_data["firmas"]
                    
                    # Si hay más de una firma, preguntar si modificar todas o solo la primera
                    modify_all = False
                    if len(firmas) > 1:
                        result = messagebox.askyesno(
                            "Múltiples certificados", 
                            f"El documento contiene {len(firmas)} certificados. ¿Desea modificar TODOS los certificados?\n\n"
                            "Seleccione 'No' para modificar solo el primer certificado."
                        )
                        modify_all = result
                    
                    # Contador para número de certificados modificados
                    modified_count = 0
                    
                    # Modificar los certificados según la elección
                    if modify_all:
                        # Modificar todos los certificados
                        for i in range(len(firmas)):
                            if "certificado_autenticacion" in firmas[i]:
                                cert_data = firmas[i]["certificado_autenticacion"]
                                if "entity_public_key" in cert_data and len(cert_data["entity_public_key"]) > 4:
                                    entity_pk = cert_data["entity_public_key"]
                                    original_char = entity_pk[4]
                                    new_char = 'd' if original_char == 'c' else 'c'
                                    cert_data["entity_public_key"] = entity_pk[:4] + new_char + entity_pk[5:]
                                    modified_count += 1
                    else:
                        # Modificar solo el primer certificado
                        if "certificado_autenticacion" in firmas[0]:
                            cert_data = firmas[0]["certificado_autenticacion"]
                            if "entity_public_key" in cert_data and len(cert_data["entity_public_key"]) > 4:
                                entity_pk = cert_data["entity_public_key"]
                                original_char = entity_pk[4]
                                new_char = 'd' if original_char == 'c' else 'c'
                                cert_data["entity_public_key"] = entity_pk[:4] + new_char + entity_pk[5:]
                                modified_count = 1
                    
                    # Actualizar los metadatos solo si se modificó algún certificado
                    if modified_count > 0:
                        # Update metadata
                        metadata["keywords"] = json.dumps(meta_data, separators=(',', ':'))
                        doc.set_metadata(metadata)
                        
                        # Save the modified PDF
                        doc.save(save_path, incremental=True, encryption=0)
                        
                        # Mensaje de éxito
                        if modify_all:
                            messagebox.showinfo("Éxito", f"Se han modificado {modified_count} certificado(s).")
                        else:
                            messagebox.showinfo("Éxito", "Se ha modificado el primer certificado.")
                        
                        self.status_var.set(f"PDF con certificado(s) modificado(s) guardado en: {save_path}")
                    else:
                        messagebox.showinfo("Información", "No se ha modificado ningún certificado.")
                        self.status_var.set("No se ha modificado ningún certificado")
                    
                    doc.close()
                    
                elif "certificado_autenticacion" in meta_data:
                    # Formato antiguo con un solo certificado
                    cert_data = meta_data["certificado_autenticacion"]
                    if "entity_public_key" in cert_data and len(cert_data["entity_public_key"]) > 4:
                        entity_pk = cert_data["entity_public_key"]
                        original_char = entity_pk[4]
                        new_char = 'd' if original_char == 'c' else 'c'
                        cert_data["entity_public_key"] = entity_pk[:4] + new_char + entity_pk[5:]
                        
                        # Update metadata
                        metadata["keywords"] = json.dumps(meta_data, separators=(',', ':'))
                        doc.set_metadata(metadata)
                        
                        # Save the modified PDF
                        doc.save(save_path, incremental=True, encryption=0)
                        
                        messagebox.showinfo("Éxito", f"Certificado modificado. Quinto carácter de entity_public_key cambiado de '{original_char}' a '{new_char}'")
                        self.status_var.set(f"PDF con certificado modificado guardado en: {save_path}")
                    else:
                        messagebox.showwarning("Advertencia", "La clave entity_public_key es demasiado corta o no existe")
                        self.status_var.set("No se pudo modificar la clave entity_public_key")
                    
                    doc.close()
                else:
                    messagebox.showerror("Error", "El PDF no contiene certificados en los metadatos")
                    self.status_var.set("El PDF no contiene certificados en los metadatos")
                    doc.close()
                    return
            
            except json.JSONDecodeError:
                messagebox.showerror("Error", "Los metadatos no están en formato JSON válido")
                self.status_var.set("Error: Formato de metadatos inválido")
                doc.close()
            
        except Exception as e:
            messagebox.showerror("Error", f"Se produjo un error: {str(e)}")
            self.status_var.set(f"Error: {str(e)}")

    def modify_signature_date(self):
        """Añadir un día a la fecha de la firma"""
        self.status_var.set("Seleccionando PDF firmado...")
        
        try:
            # Open file dialog to select signed PDF
            file_path = filedialog.askopenfilename(
                title="Seleccionar PDF firmado",
                filetypes=[("Archivos PDF", "*.pdf"), ("Todos los archivos", "*.*")]
            )
            
            if not file_path:
                self.status_var.set("Operación cancelada")
                return
            
            # First, make a copy of the original file that we'll modify
            save_path = filedialog.asksaveasfilename(
                title="Guardar PDF con fecha modificada",
                defaultextension=".pdf",
                filetypes=[("Archivos PDF", "*.pdf")],
                initialfile="fecha_mod_" + os.path.basename(file_path)
            )
            
            if not save_path:
                self.status_var.set("Guardado cancelado")
                return
                    
            # Copy the original file to the new location
            with open(file_path, "rb") as src_file:
                with open(save_path, "wb") as dst_file:
                    dst_file.write(src_file.read())
            
            # Now open the new file for modification
            doc = fitz.open(save_path)
            metadata = doc.metadata
            
            if "keywords" not in metadata:
                messagebox.showerror("Error", "El PDF no contiene metadatos de firma")
                self.status_var.set("El PDF no contiene metadatos de firma")
                doc.close()
                return
                    
            try:
                # Parse metadata
                meta_data = json.loads(metadata.get("keywords", "{}"))
                
                # Verificar si hay múltiples firmas
                if "firmas" in meta_data and meta_data["firmas"]:
                    # Formato nuevo con múltiples firmas
                    firmas = meta_data["firmas"]
                    
                    # Si hay más de una firma, preguntar si modificar todas o solo la primera
                    modify_all = False
                    if len(firmas) > 1:
                        result = messagebox.askyesno(
                            "Múltiples firmas", 
                            f"El documento contiene {len(firmas)} firmas. ¿Desea modificar la fecha de TODAS las firmas?\n\n"
                            "Seleccione 'No' para modificar solo la primera firma."
                        )
                        modify_all = result
                    
                    # Contador para número de firmas modificadas
                    modified_count = 0
                    
                    # Modificar las fechas según la elección
                    if modify_all:
                        # Modificar todas las firmas
                        for i in range(len(firmas)):
                            if "fecha_firma" in firmas[i]:
                                try:
                                    # Obtener fecha original
                                    original_date = firmas[i]["fecha_firma"]
                                    fecha_obj = datetime.fromisoformat(original_date)
                                    
                                    # Sumar 1 día
                                    nueva_fecha_obj = fecha_obj + timedelta(days=1)
                                    
                                    # Convertir a string ISO
                                    nueva_fecha = nueva_fecha_obj.isoformat()
                                    
                                    # Actualizar fecha
                                    firmas[i]["fecha_firma"] = nueva_fecha
                                    modified_count += 1
                                except (ValueError, TypeError):
                                    # Si hay error al procesar la fecha, la omitimos
                                    continue
                    else:
                        # Modificar solo la primera firma
                        if "fecha_firma" in firmas[0]:
                            try:
                                # Obtener fecha original
                                original_date = firmas[0]["fecha_firma"]
                                fecha_obj = datetime.fromisoformat(original_date)
                                
                                # Sumar 1 día
                                nueva_fecha_obj = fecha_obj + timedelta(days=1)
                                
                                # Convertir a string ISO
                                nueva_fecha = nueva_fecha_obj.isoformat()
                                
                                # Actualizar fecha
                                firmas[0]["fecha_firma"] = nueva_fecha
                                modified_count = 1
                            except (ValueError, TypeError):
                                # Si hay error al procesar la fecha
                                messagebox.showwarning("Advertencia", "Formato de fecha no válido")
                                self.status_var.set("Formato de fecha no válido")
                    
                    # Actualizar los metadatos solo si se modificó alguna firma
                    if modified_count > 0:
                        # Update metadata
                        metadata["keywords"] = json.dumps(meta_data, separators=(',', ':'))
                        doc.set_metadata(metadata)
                        
                        # Save the modified PDF
                        doc.save(save_path, incremental=True, encryption=0)
                        
                        # Mensaje de éxito
                        if modify_all:
                            messagebox.showinfo("Éxito", f"Se ha añadido un día a la fecha de {modified_count} firma(s).")
                        else:
                            messagebox.showinfo("Éxito", "Se ha añadido un día a la fecha de la primera firma.")
                        
                        self.status_var.set(f"PDF con fecha(s) modificada(s) guardado en: {save_path}")
                    else:
                        messagebox.showinfo("Información", "No se ha modificado ninguna fecha.")
                        self.status_var.set("No se ha modificado ninguna fecha")
                    
                    doc.close()
                    
                elif "fecha_firma" in meta_data:
                    # Formato antiguo con una sola firma
                    try:
                        # Obtener fecha original
                        original_date = meta_data["fecha_firma"]
                        fecha_obj = datetime.fromisoformat(original_date)
                        
                        # Sumar 1 día
                        nueva_fecha_obj = fecha_obj + timedelta(days=1)
                        
                        # Convertir a string ISO
                        nueva_fecha = nueva_fecha_obj.isoformat()
                        
                        # Actualizar fecha
                        meta_data["fecha_firma"] = nueva_fecha
                        
                        # Update metadata
                        metadata["keywords"] = json.dumps(meta_data, separators=(',', ':'))
                        doc.set_metadata(metadata)
                        
                        # Save the modified PDF
                        doc.save(save_path, incremental=True, encryption=0)
                        
                        messagebox.showinfo("Éxito", f"Se ha añadido un día a la fecha de firma")
                        self.status_var.set(f"PDF con fecha modificada guardado en: {save_path}")
                    except (ValueError, TypeError):
                        messagebox.showwarning("Advertencia", "Formato de fecha no válido")
                        self.status_var.set("Formato de fecha no válido")
                    
                    doc.close()
                else:
                    messagebox.showerror("Error", "El PDF no contiene fechas de firma en los metadatos")
                    self.status_var.set("El PDF no contiene fechas de firma en los metadatos")
                    doc.close()
                    return
                
            except json.JSONDecodeError:
                messagebox.showerror("Error", "Los metadatos no están en formato JSON válido")
                self.status_var.set("Error: Formato de metadatos inválido")
                doc.close()
            
        except Exception as e:
            messagebox.showerror("Error", f"Se produjo un error: {str(e)}")
            self.status_var.set(f"Error: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PDFModifierApp(root)
    root.mainloop()