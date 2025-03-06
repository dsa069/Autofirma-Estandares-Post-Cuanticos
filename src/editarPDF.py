import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import fitz  # PyMuPDF
import json
import os

class PDFModifierApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF y Firma Modificador")
        self.root.geometry("500x320")
        
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
        btn_modify_signature = ttk.Button(btn_frame2, text="Modificar tercer carácter de la firma por 'x'",
                                       command=self.modify_signature)
        btn_modify_signature.pack(fill=tk.X, padx=10, pady=5)
        
        btn_frame3 = ttk.LabelFrame(main_frame, text="Opción 3")
        btn_frame3.pack(fill=tk.X, pady=5)
        btn_modify_pubkey = ttk.Button(btn_frame3, text="Modificar quinto carácter de entity_public_key por 'x'",
                                     command=self.modify_pubkey)
        btn_modify_pubkey.pack(fill=tk.X, padx=10, pady=5)
        
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
                
                if "firma" not in meta_data:
                    messagebox.showerror("Error", "El PDF no contiene firma en los metadatos")
                    self.status_var.set("El PDF no contiene firma en los metadatos")
                    doc.close()
                    return
                
                # Get the signature and modify it
                firma = meta_data["firma"]
                original_char = firma[2] if len(firma) > 2 else "?"
                
                # Replace third character with 'c' instead of 'x'
                if len(firma) > 2:
                    modified_firma = firma[:2] + "c" + firma[3:]
                    meta_data["firma"] = modified_firma
                    
                    # Update metadata
                    metadata["keywords"] = json.dumps(meta_data)
                    doc.set_metadata(metadata)
                    
                    # Save the modified PDF WITH incremental mode
                    doc.save(save_path, incremental=True, encryption=0)
                    doc.close()
                    
                    messagebox.showinfo("Éxito", f"Firma modificada. Tercer carácter cambiado de '{original_char}' a 'c'")
                    self.status_var.set(f"PDF con firma modificada guardado en: {save_path}")
                else:
                    messagebox.showwarning("Advertencia", "La firma es demasiado corta para modificar el tercer carácter")
                    self.status_var.set("La firma es demasiado corta")
                    doc.close()
            
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
                
                if "certificado_autenticacion" not in meta_data:
                    messagebox.showerror("Error", "El PDF no contiene certificado en los metadatos")
                    self.status_var.set("El PDF no contiene certificado en los metadatos")
                    doc.close()
                    return
                
                # Get the certificate
                cert_data = meta_data["certificado_autenticacion"]
                
                if "entity_public_key" not in cert_data:
                    messagebox.showerror("Error", "El certificado no contiene entity_public_key")
                    self.status_var.set("El certificado no contiene entity_public_key")
                    doc.close()
                    return
                
                # Modify the fifth character of entity_public_key with 'c' instead of 'x'
                entity_pk = cert_data["entity_public_key"]
                original_char = entity_pk[4] if len(entity_pk) > 4 else "?"
                
                if len(entity_pk) > 4:
                    modified_pk = entity_pk[:4] + "c" + entity_pk[5:]
                    cert_data["entity_public_key"] = modified_pk
                    meta_data["certificado_autenticacion"] = cert_data
                    
                    # Update metadata
                    metadata["keywords"] = json.dumps(meta_data)
                    doc.set_metadata(metadata)
                    
                    # Save the modified PDF
                    doc.save(save_path, incremental=True, encryption=0)
                    messagebox.showinfo("Éxito", f"Certificado modificado. Quinto carácter de entity_public_key cambiado de '{original_char}' a 'c'")
                    self.status_var.set(f"PDF con certificado modificado guardado en: {save_path}")
                else:
                    messagebox.showwarning("Advertencia", "La clave entity_public_key es demasiado corta")
                    self.status_var.set("La clave es demasiado corta")
                    doc.close()
            
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