# Escáner de Vulnerabilidades Web

Una aplicación web para escanear vulnerabilidades en sitios web, con una interfaz gráfica fácil de usar construida con Flask.

## Características

- Escaneo de vulnerabilidades comunes:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Clickjacking
  - Security Headers faltantes
  - Open Redirect
  - CSRF (Cross-Site Request Forgery)
- Interfaz web interactiva y amigable
- Resultados en tiempo real
- Generación de informes en PDF
- Categorización de vulnerabilidades por nivel de riesgo

## Requisitos

- Python 3.8 o superior
- Chrome WebDriver para las pruebas con Selenium

## Instalación

1. Clona este repositorio o descarga los archivos

2. Instala las dependencias:
   ```
   pip install -r requirements.txt
   ```

3. Asegúrate de tener instalado Chrome WebDriver y que esté en tu PATH (para las pruebas XSS con Selenium)

## Estructura del Proyecto

```
escaner-vulnerabilidades/
│
├── web_interface.py            # Aplicación principal Flask
├── static/                     # Archivos estáticos
│   └── css/
│       └── styles.css          # Estilos CSS
│
├── templates/                  # Plantillas HTML
│   ├── index.html              # Página principal
│   └── results.html            # Página de resultados
│
├── reports/                    # Directorio para los informes generados (se crea automáticamente)
│
├── requirements.txt            # Dependencias del proyecto
└── README.md                   # Este archivo
```

## Uso

1. Ejecuta la aplicación web:
   ```
   python web_interface.py
   ```

2. Abre tu navegador web y accede a:
   ```
   http://127.0.0.1:5000
   ```

3. Ingresa la URL del sitio web que deseas escanear y haz clic en "Escanear"

4. La aplicación ejecutará las pruebas y mostrará los resultados en tiempo real

5. Una vez completado, podrás descargar un informe en PDF con los resultados

## Advertencia

Esta herramienta está diseñada exclusivamente para fines educativos y para evaluar la seguridad de sitios web propios o que tengas permiso explícito para auditar. El uso de esta herramienta contra sitios web sin autorización puede constituir un delito.

## Personalización

Puedes personalizar las pruebas o agregar más verificaciones modificando el archivo `web_interface.py`.

## Nota sobre Selenium

La prueba XSS con Selenium requiere tener instalado Chrome WebDriver. Si no lo tienes instalado, puedes comentar la sección correspondiente en el código o instalar el WebDriver desde [la página oficial de Chrome WebDriver](https://sites.google.com/a/chromium.org/chromedriver/downloads).