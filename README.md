# AutoFirma con Estándares Post-Cuánticos

Herramienta de firma digital para documentos PDF que implementa algoritmos criptográficos resistentes a ataques cuánticos. Este proyecto proporciona una solución completa para la creación, gestión y verificación de firmas digitales utilizando algoritmos post-cuánticos como SPHINCS+ y Dilithium.

## Características Principales

- **Firma Digital Post-Cuántica**: Firma documentos PDF utilizando algoritmos resistentes a computación cuántica.
- **Validación de Firmas**: Verifica la autenticidad e integridad de firmas digitales existentes.
- **Generación de Certificados**: Crea y gestiona certificados digitales con claves post-cuánticas.
- **Firma Visual**: Añade representaciones visuales de las firmas dentro del documento.
- **Interfaz Gráfica Amigable**: Diseño moderno e intuitivo para facilitar todas las operaciones.
- **Firmas en Cascada**: Soporte para múltiples firmas superpuestas en un documento.
- **Integración con Sistema**: Protocolo personalizado para verificación de firmas (`autofirma://`).

## Componentes del Proyecto

El proyecto consta de tres aplicaciones principales:

1. **FirmaDocumentos** (`firmaApp.py`): Aplicación principal para firmar y verificar documentos PDF.
2. **EntidadGeneradora** (`entGenApp.py`): Generador de certificados digitales y claves de entidad.
3. **Herramienta de Modificación** (`editarPDF.py`): Utilidad para pruebas de integridad y modificación de documentos.

## Requisitos de Instalación

### Dependencias

- Python 3.8 o superior
- Bibliotecas Python:
  - customtkinter
  - tkinterdnd2
  - PyMuPDF (fitz)
  - pycryptodome
  - pillow
  - psutil (para Windows)

Para instalar las dependencias necesarias:

```bash
pip install customtkinter tkinterdnd2 PyMuPDF pycryptodome pillow psutil
```

### Algoritmos Criptográficos

- SPHINCS+: Implementado en el paquete `package.sphincs`
- Dilithium: Disponible a través de `dilithium_py.ml_dsa`

## Uso

### Firma de Documentos

1. Inicie la aplicación FirmaDocumentos
2. Seleccione o arrastre un documento PDF
3. Haga clic en "Firmar"
4. Seleccione su certificado digital y proporcione la contraseña
5. Opcionalmente, añada una firma visual al documento
6. Guarde el documento firmado

### Verificación de Firmas

1. Abra la aplicación FirmaDocumentos
2. Seleccione o arrastre un documento PDF firmado
3. Haga clic en "Verificar"
4. Revise los resultados de la verificación

### Generación de Certificados

1. Inicie la aplicación EntidadGeneradora
2. Genere nuevas claves de entidad o seleccione una existente
3. Complete los datos del certificado (nombre, DNI, etc.)
4. Establezca una contraseña segura
5. El certificado se guardará en la carpeta de certificados del usuario

## Estructura del Proyecto

Autofirma-Estandares-Post-Cuanticos/
├── package/               # Implementaciones de algoritmos criptográficos
├── src/
│   ├── backend/           # Lógica de negocio y funciones criptográficas
│   │   ├── funcComunes.py # Funciones compartidas
│   │   ├── funcFirma.py   # Operaciones de firma
│   │   └── funcEntGen.py  # Generación de certificados
│   ├── frontend/          # Componentes de interfaz gráfica
│   │   ├── compComunes.py # Componentes UI comunes
│   │   ├── compFirma.py   # Componentes de firma
│   │   └── compEntGen.py  # Componentes para generación de certificados
│   ├── img/               # Recursos gráficos (iconos, imágenes)
│   ├── logs/              # Registros de la aplicación
│   ├── firmaApp.py        # Aplicación de firma de documentos
│   ├── entGenApp.py       # Generador de certificados
│   ├── editarPDF.py       # Herramienta para pruebas de integridad
│   ├── firmaApp.spec      # Configuración de compilación PyInstaller
│   └── entGenApp.spec     # Configuración de compilación PyInstaller
└── LICENSE           

# Compilación a Ejecutable

Para generar archivos ejecutables (.exe en Windows):

## Compilar aplicación de firma
python -m PyInstaller --clean firmaApp.spec

## Compilar generador de certificados
python -m PyInstaller --clean entGenApp.spec

Los ejecutables generados estarán disponibles en el directorio dist.

# Pruebas de Integridad
La herramienta editarPDF.py permite realizar pruebas de integridad:

1. Modificar palabras en el documento original
2. Alterar firmas digitales
3. Modificar metadatos de certificados
4. Cambiar fechas de firmas
5. Estas funciones son útiles para comprobar los mecanismos de protección implementados.

# Verificación de Firmas Digitales
El proyecto incluye un protocolo personalizado autofirma:// que permite la verificación rápida de documentos PDF:

1. Al hacer clic en una firma visual dentro de un PDF, se activa el protocolo.
2. La aplicación AutoFirma se inicia automáticamente y verifica el documento.
3. Se muestra un informe con los resultados de la validación.