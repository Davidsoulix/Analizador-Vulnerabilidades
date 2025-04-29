#!/usr/bin/env python3
"""
Punto de entrada principal para la aplicación de escaneo de vulnerabilidades web.
Este script inicia la interfaz web para el escáner de vulnerabilidades.
"""

import os
from web_interface import app

if __name__ == "__main__":
    # Crear directorios necesarios si no existen
    if not os.path.exists('reports'):
        os.makedirs('reports')
    if not os.path.exists('static/css'):
        os.makedirs('static/css')
        
    # Verificar que los directorios de plantillas y estáticos existen
    if not os.path.exists('templates'):
        print("Error: El directorio 'templates/' no existe.")
        exit(1)
    if not os.path.exists('static/css/styles.css'):
        print("Error: El archivo 'static/css/styles.css' no existe.")
        exit(1)
        
    print("\n\033[92m----- Escáner de Vulnerabilidades Web -----\033[0m")
    print("\033[94mIniciando la aplicación web...\033[0m")
    print("\033[94mAccede a http://127.0.0.1:5000 en tu navegador\033[0m")
    print("\033[93mPara detener la aplicación, presiona Ctrl+C\033[0m\n")
    
    # Iniciar la aplicación Flask
    app.run(host='0.0.0.0', port=5000, debug=False)