from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import os
import sys
import threading
import queue
import time
from io import StringIO
import contextlib
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

app = Flask(__name__)
app.secret_key = 'vulnerability_scanner_secret_key'

# Crear directorio para informes si no existe
if not os.path.exists('reports'):
    os.makedirs('reports')

# Cola para comunicación entre el hilo de escaneo y la aplicación web
scan_queue = queue.Queue()
results_queue = queue.Queue()

# Funciones del escáner

# PDF report initialization
def generate_report(results, filename):
    pdf_path = os.path.join('reports', filename)
    pdf = canvas.Canvas(pdf_path, pagesize=letter)
    pdf.setTitle("Reporte de Vulnerabilidades de Aplicaciones Web")
    pdf.drawString(100, 750, "Reporte de Vulnerabilidades de Aplicaciones Web")
    y = 720
    for vuln, (status, level) in results.items():
        pdf.drawString(80, y, f"{vuln}: {status} (Risk: {level})")
        y -= 20
    pdf.save()
    return pdf_path

# SQL Injection Test
def check_sql_injection(url):
    results_queue.put(f"Probando SQL Injection en {url}...")
    test_payloads = ["' OR '1'='1", '" OR "1"="1', "'--", "' OR 1=1 --"]
    vulnerable = False
    for payload in test_payloads:
        test_url = f"{url}?id={payload}"
        try:
            res = requests.get(test_url)
            if any(error in res.text.lower() for error in ["sql", "syntax", "mysql", "native client"]):
                vulnerable = True
                break
        except requests.exceptions.RequestException as e:
            results_queue.put(f"Error en la solicitud: {str(e)}")
            return ("Error", "Unknown")
    
    result = ("Vulnerable" if vulnerable else "Safe", "High" if vulnerable else "Low")
    results_queue.put(f"SQL Injection: {result[0]} (Risk: {result[1]})")
    return result

# XSS Test
def check_xss(url):
    results_queue.put(f"Probando XSS en {url}...")
    payload = "<script>alert(1)</script>"
    try:
        res = requests.get(f"{url}?q={payload}")
        if payload in res.text:
            result = ("Vulnerable", "High")
        else:
            result = ("Safe", "Low")
    except requests.exceptions.RequestException as e:
        results_queue.put(f"Error en la solicitud: {str(e)}")
        return ("Error", "Unknown")
    
    results_queue.put(f"XSS: {result[0]} (Risk: {result[1]})")
    return result

# Clickjacking Test
def check_clickjacking(url):
    results_queue.put(f"Probando Clickjacking en {url}...")
    try:
        headers = requests.get(url).headers
        if "X-Frame-Options" not in headers:
            result = ("Vulnerable", "Medium")
        else:
            result = ("Safe", "Low")
    except requests.exceptions.RequestException as e:
        results_queue.put(f"Error en la solicitud: {str(e)}")
        return ("Error", "Unknown")
    
    results_queue.put(f"Clickjacking: {result[0]} (Risk: {result[1]})")
    return result

# Security Headers Test
def check_security_headers(url):
    results_queue.put(f"Verificando Security Headers en {url}...")
    expected_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]
    try:
        res = requests.get(url)
        missing = [h for h in expected_headers if h not in res.headers]
        if missing:
            result = (f"Missing: {', '.join(missing)}", "Medium")
        else:
            result = ("All present", "Low")
    except requests.exceptions.RequestException as e:
        results_queue.put(f"Error en la solicitud: {str(e)}")
        return ("Error", "Unknown")
    
    results_queue.put(f"Security Headers: {result[0]} (Risk: {result[1]})")
    return result

# Open Redirect Test
def check_open_redirect(url):
    results_queue.put(f"Probando Open Redirect en {url}...")
    test_url = url + "/redirect?url=https://evil.com"
    try:
        res = requests.get(test_url, allow_redirects=False)
        if "Location" in res.headers and "evil.com" in res.headers["Location"]:
            result = ("Vulnerable", "High")
        else:
            result = ("Safe", "Low")
    except requests.exceptions.RequestException as e:
        results_queue.put(f"Error en la solicitud: {str(e)}")
        return ("Error", "Unknown")
    
    results_queue.put(f"Open Redirect: {result[0]} (Risk: {result[1]})")
    return result

# CSRF Token Test (basic)
def check_csrf(url):
    results_queue.put(f"Probando CSRF en {url}...")
    try:
        res = requests.get(url)
        soup = BeautifulSoup(res.text, 'html.parser')
        forms = soup.find_all('form')
        if forms:
            for form in forms:
                inputs = form.find_all('input')
                if not any("csrf" in inp.get("name", "").lower() for inp in inputs):
                    result = ("Missing CSRF Token", "Medium")
                    break
            else:
                result = ("Token Present", "Low")
        else:
            result = ("No Forms Found", "Low")
    except Exception as e:
        results_queue.put(f"Error: {str(e)}")
        return (f"Error: {str(e)}", "Unknown")
    
    results_queue.put(f"CSRF: {result[0]} (Risk: {result[1]})")
    return result

# Función extendida para probar XSS con Selenium
def check_xss_selenium(url):
    results_queue.put(f"Probando XSS con Selenium en {url}...")
    try:
        # Usar opciones headless para que no se abra el navegador visualmente
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        
        script = "<script>alert('XSS')</script>"
        inputs = driver.find_elements(By.TAG_NAME, 'input')
        xss_detected = False
        
        for input_field in inputs:
            try:
                input_field.send_keys(script)
                try:
                    input_field.submit()
                except:
                    pass
                
                # Comprobar si aparece una alerta
                try:
                    alert = driver.switch_to.alert
                    alert.accept()
                    xss_detected = True
                    break
                except:
                    pass
            except:
                continue
        
        driver.quit()
        
        if xss_detected:
            result = ("Vulnerable (Selenium)", "High")
        else:
            result = ("Safe (Selenium)", "Low")
    except Exception as e:
        results_queue.put(f"Error en la prueba con Selenium: {str(e)}")
        return ("Error (Selenium)", "Unknown")
    
    results_queue.put(f"XSS (Selenium): {result[0]} (Risk: {result[1]})")
    return result

# Función principal de escaneo
def scan(url, session_id):
    results_queue.put("Iniciando escaneo de vulnerabilidades...")
    results = {}
    
    # Verificar que la URL es válida
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        requests.get(url, timeout=10)
    except requests.exceptions.RequestException as e:
        results_queue.put(f"Error: No se puede conectar a {url}: {str(e)}")
        return None
    
    results_queue.put(f"Escaneando {url} y sus vulnerabilidades...")
    
    # Ejecutar las pruebas
    results["SQL Injection"] = check_sql_injection(url)
    results["XSS"] = check_xss(url)
    results["Clickjacking"] = check_clickjacking(url)
    results["Open Redirect"] = check_open_redirect(url)
    results["Security Headers"] = check_security_headers(url)
    results["CSRF"] = check_csrf(url)
    
    # Prueba adicional de XSS con Selenium
    try:
        results["XSS (Selenium)"] = check_xss_selenium(url)
    except Exception as e:
        results_queue.put(f"Error en la prueba XSS con Selenium: {str(e)}")
        results["XSS (Selenium)"] = ("Error", "Unknown")
    
    results_queue.put("\n--- Resultados del Scan ---")
    for vuln, (status, risk) in results.items():
        results_queue.put(f"{vuln}: {status} (Risk: {risk})")
    
    # Generar reporte PDF
    filename = f"vulnerability_report_{session_id}.pdf"
    pdf_path = generate_report(results, filename)
    results_queue.put(f"Reporte PDF generado: {filename}")
    
    # Señalar que se completó el escaneo
    results_queue.put("SCAN_COMPLETE")
    
    return results, pdf_path

# Rutas de la aplicación web
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    url = request.form.get('url')
    if not url:
        flash('Por favor, ingrese una URL válida', 'danger')
        return redirect(url_for('index'))
    
    # Generar ID de sesión único
    session_id = str(int(time.time()))
    
    # Iniciar el escaneo en un hilo separado
    thread = threading.Thread(target=scan, args=(url, session_id))
    thread.daemon = True
    thread.start()
    
    return redirect(url_for('results', session_id=session_id))

@app.route('/results/<session_id>')
def results(session_id):
    return render_template('results.html', session_id=session_id)

@app.route('/get_results')
def get_results():
    # Obtener los resultados acumulados hasta ahora
    results = []
    while not results_queue.empty():
        result = results_queue.get()
        if result == "SCAN_COMPLETE":
            return {'results': results, 'complete': True}
        results.append(result)
    
    return {'results': results, 'complete': False}

@app.route('/download/<session_id>')
def download_report(session_id):
    filename = f"vulnerability_report_{session_id}.pdf"
    file_path = os.path.join('reports', filename)
    
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        flash('El reporte no está disponible', 'danger')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)