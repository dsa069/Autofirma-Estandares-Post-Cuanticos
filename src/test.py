import time
import sys
import os

try:
    # Importar la implementación ML-DSA (Dilithium)
    from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
except ImportError:
    print("Error: No se pudo importar dilithium_py.")
    print("Por favor, asegúrate de que está instalado correctamente: pip install dilithium_py")
    sys.exit(1)

def format_bytes(size):
    """Formatea bytes a KB o MB para mejor legibilidad"""
    if size < 1024:
        return f"{size} bytes"
    elif size < 1024 * 1024:
        return f"{size/1024:.2f} KB"
    else:
        return f"{size/(1024*1024):.2f} MB"

def test_dilithium():
    """Prueba básica de las funciones de Dilithium usando ML-DSA"""
    
    print("\n===== PRUEBA DE DILITHIUM (ML-DSA) =====\n")
    
    # Mapear los tres niveles de seguridad disponibles
    security_levels = {
        "ML_DSA_44 (Dilithium2)": ML_DSA_44,
        "ML_DSA_65 (Dilithium3)": ML_DSA_65,
        "ML_DSA_87 (Dilithium5)": ML_DSA_87
    }
    
    for name, algo in security_levels.items():
        print(f"\n----- Probando {name} -----")
        
        try:
            # 1. Generación de claves
            print("\nGenerando par de claves...")
            start_time = time.time()
            pk, sk = algo.keygen()
            end_time = time.time()
            
            print(f"✓ Tiempo de generación: {(end_time - start_time):.4f} segundos")
            print(f"✓ Tamaño de clave pública: {format_bytes(len(pk))}")
            print(f"✓ Tamaño de clave secreta: {format_bytes(len(sk))}")
            
            # 2. Firma de mensaje
            message = b"Este es un mensaje de prueba para firmar con ML-DSA"
            print("\nFirmando mensaje...")
            start_time = time.time()
            signature = algo.sign(sk, message)  # Nota: orden de parámetros invertido (sk, msg)
            end_time = time.time()
            
            print(f"✓ Tiempo de firma: {(end_time - start_time):.4f} segundos")
            print(f"✓ Tamaño de firma: {format_bytes(len(signature))}")
            
            # 3. Verificación de firma válida
            print("\nVerificando firma válida...")
            start_time = time.time()
            is_valid = algo.verify(pk, message, signature)  # API: verify(pk, msg, sig)
            end_time = time.time()
            
            print(f"✓ Tiempo de verificación: {(end_time - start_time):.4f} segundos")
            print(f"✓ Firma válida: {is_valid}")
            
            # 4. Verificación de firma con mensaje alterado
            altered_message = b"Este es un mensaje ALTERADO para verificacion"
            print("\nVerificando firma con mensaje alterado...")
            start_time = time.time()
            is_valid_altered = algo.verify(pk, altered_message, signature)
            end_time = time.time()
            
            print(f"✓ Firma con mensaje alterado: {is_valid_altered} (debería ser False)")
            
            # 5. Prueba con pk incorrecta
            print("\nVerificando firma con clave pública incorrecta...")
            pk_new, _ = algo.keygen()
            is_valid_wrong_pk = algo.verify(pk_new, message, signature)
            print(f"✓ Firma con clave pública incorrecta: {is_valid_wrong_pk} (debería ser False)")
            
        except Exception as e:
            print(f"❌ Error al probar {name}: {e}")
    
    print("\n===== FIN DE LA PRUEBA =====\n")

if __name__ == "__main__":
    test_dilithium()