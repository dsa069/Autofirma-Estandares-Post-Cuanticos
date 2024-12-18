import sys
import os

# Añadir la carpeta padre (donde está 'package') a sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)  # Subir un nivel desde 'src'
sys.path.insert(0, parent_dir)

# Importar Sphincs desde el paquete
from package.sphincs import Sphincs

sphincs = Sphincs()

sphincs.set_w(4)

sk, pk = sphincs.generate_key_pair()

m = b'What are quantum mechanics? I dont know. People who repair quantums, I suppose.'
signature = sphincs.sign(m, sk)

print(sphincs.verify(m, signature, pk))