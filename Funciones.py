try:
    import os
    import subprocess
    import requests
    import logging
    import nmap
    import requests
    import socket
    import shodan
    from lxml import html
    from bs4 import BeautifulSoup
    from PIL.ExifTags import TAGS, GPSTAGS
    from PIL import Image
except ImportError as e:
    os.system("pip install -r requirements.txt")
    print("Se instalo el archivo requirements.txt, vuevla a ejecutar")
    exit()


logging.basicConfig(filename='app.log', level=logging.INFO)

# Escaneo de puertos
def scanPorts(IP):
    try:
        nm = nmap.PortScanner()
        nm.scan(IP)
        for host in nm.all_hosts():
            puertos = []
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    if 'open' not in nm[host][proto][port].values():
                        puertos.append(port)
            for i in puertos:
                nm[host][proto].pop(i)
        mapa = nm.csv()
        if mapa:
            mapa = mapa.replace(';', ',')
            with open('OpenPorts.csv', 'w') as f:
                f.write(mapa)
            print('Los puertos abiertos se han guardado en el archivo '
                  'OpenPorts.csv')
        else:
            print('No se encontraron puertos abiertos')
    except Exception as e:
        logging.error('Ha ocurrido un error: ' + str(e))
        return 'Ha ocurrido un error: ' + str(e)


# Web Scraping
def scrapingImages(url):
    print("\nObteniendo imagenes de la url:" + url)
    try:
        response = requests.get(url)
        parsed_body = html.fromstring(response.text)
        images = parsed_body.xpath('//img/@src')
        print ('Se encontraron %s imagenes' % len(images))
        os.system("mkdir images")
        for image in images:
            if image.startswith("http") is False:
                download = url + image
            else:
                download = image
            print(download)
            r = requests.get(download)
            f = open('images/%s' % download.split('/')[-1], 'wb')
            f.write(r.content)
            f.close()
    except Exception as e:
        logging.error('Ha ocurrido un error: ' + str(e))
        return 'Ha ocurrido un error: ' + str(e)
        print ("Error conexion con " + url)


def scrapingPDF(url):
    print("\nObteniendo pdfs de la url:" + url)
    try:
        response = requests.get(url)
        parsed_body = html.fromstring(response.text)
        pdfs = parsed_body.xpath('//a[@href[contains(., ".pdf")]]/@href')
        if len(pdfs) > 0:
            os.system("mkdir pdfs")
        print ('Se encontraron %s pdf' % len(pdfs))
        for pdf in pdfs:
            if pdf.startswith("http") is False:
                download = url + pdf
            else:
                download = pdf
            print(download)
            r = requests.get(download)
            f = open('pdfs/%s' % download.split('/')[-1], 'wb')
            f.write(r.content)
            f.close()
    except Exception as e:
        logging.error('Ha ocurrido un error: ' + str(e))
        return 'Ha ocurrido un error: ' + str(e)
        print("Error conexion con " + url)


def scrapingLinks(url):
    print("\nObteniendo links de la url:" + url)
    try:
        response = requests.get(url)
        parsed_body = html.fromstring(response.text)
        links = parsed_body.xpath('//a/@href')
        print('Se encontraron %s links' % len(links))
        for link in links:
            print(link)
    except Exception as e:
        logging.error('Ha ocurrido un error: ' + str(e))
        return 'Ha ocurrido un error: ' + str(e)
        print("Error conexion con " + url)


# Revision de Encabezados
def checkHeaders(url):
    try:
        response = requests.get(url)
        headers = response.headers
        for x, y in headers.items():
            print('%s : %s' % (x, y))
            with open('Encabezados.txt', 'a') as f:
                f.write('%s : %s \n' % (x, y))
    except Exception as e:
        logging.error('Ha ocurrido un error: ' + str(e))
        return 'Ha ocurrido un error: ' + str(e)


# Información de Sockets
def socketInfo(hostname):
    try:
        addrInfo = socket.getaddrinfo(hostname, 80)
        nombres = ['Familia', 'Tipo', 'Protocolo TCP', 'Flags', 'IP/Puerto']
        counter = 1
        for i in addrInfo:
            c = 0
            print('Información Socket {}'.format(str(counter)))
            print('------------------------')
            for e in i:
                    print(nombres[c],':',e)
                    c += 1
            print('\n')
            counter += 1
    except Exception as e:
        logging.error('Ha ocurrido un error: ' + str(e))
        return 'Ha ocurrido un error: ' + str(e)

# Encriptación del mensaje
def cifrado(msj, key):
    try:
        SYMBOLS = 'ABCDEFGHIJKLMNÑOPQRSTUVWXYZÁÉÍÓÚÜabcdefghijklmnñopqrstuvwxyzáéíóúü1234567890 !?.'
        translated = ''
        if type(key) == str:
            key = len(key)
        for symbol in msj:
            if symbol in SYMBOLS:
                symbolIndex = SYMBOLS.find(symbol)
                translatedIndex = symbolIndex + key
                
                if translatedIndex >= len(SYMBOLS):
                    translatedIndex = translatedIndex - len(SYMBOLS)
                elif translatedIndex < 0:
                    translatedIndex = translatedIndex + len(SYMBOLS)

                translated = translated + SYMBOLS[translatedIndex]
            else:
                translated = translated + symbol
                
        print('El mensaje encriptado es: ', translated)
    except Exception as e:
        logging.error("Ha ocurrido un error: " + str(e))
        return ("Ha ocurrido un error: " + str(e))

    
# Obtención de metadata de imagenes
def decode_gps_info(exif):
    try:
        gpsinfo = {}
        if 'GPSInfo' in exif:
            Nsec = exif['GPSInfo'][2][2]
            Nmin = exif['GPSInfo'][2][1]
            Ndeg = exif['GPSInfo'][2][0]
            Wsec = exif['GPSInfo'][4][2]
            Wmin = exif['GPSInfo'][4][1]
            Wdeg = exif['GPSInfo'][4][0]
            if exif['GPSInfo'][1] == 'N':
                Nmult = 1
            else:
                Nmult = -1
            if exif['GPSInfo'][3] == 'E':
                Wmult = 1
            else:
                Wmult = -1
            Lat = Nmult * (Ndeg + (Nmin + Nsec/60.0)/60.0)
            Lng = Wmult * (Wdeg + (Wmin + Wsec/60.0)/60.0)
            exif['GPSInfo'] = {"Lat" : Lat, "Lng" : Lng}
    except Exception as e:
        logging.error("Ha ocurrido un error: " + str(e))
        return ("Ha ocurrido un error: " + str(e))
        

def get_exif_metadata(image_path):
    try:
        ret = {}
        image = Image.open(image_path)
        exifinfo = image._getexif()
        if exifinfo is not None:
            for tag, value in exifinfo.items():
                decoded = TAGS.get(tag, tag)
                ret[decoded] = value
        decode_gps_info(ret)
        return ret
    except Exception as e:
        logging.error("Ha ocurrido un error: " + str(e))
        return ("Ha ocurrido un error: " + str(e))

    
def printMeta(ruta):
    try:
        os.chdir(ruta)
        for root, dirs, files in os.walk(".", topdown=False):
            for name in files:
                with open('Metadata.txt', 'a') as f:
                    f.write("[+] Metadata for file: %s \n\n" %(name))
                try:
                    exifData = {}
                    exif = get_exif_metadata(name)
                    for metadata in exif:
                        with open('Metadata.txt', 'a') as f:
                            f.write("Metadata: %s - Value: %s \n" %(metadata, exif[metadata]))
                except:
                    import sys, traceback
                    traceback.print_exc(file=sys.stdout)
        print("La metadata se guardo en Metadata.txt")
    except Exception as e:
        logging.error("Ha ocurrido un error: " + str(e))
        return ("Ha ocurrido un error: " + str(e))

# API Shodan
def API(api_key, search):
    try:
        objShodan = shodan.Shodan(api_key)
        resultados = objShodan.search(search)
        print("Numéro de resultados: ", len(resultados["matches"]))
        i = 1
        for match in resultados["matches"]:
            print("[+] Resultado ", i)
            i = i+1
            if match["port"] is not None:
                print("Puerto: ", match["port"])
            if match["location"] is not None:
                if match["location"]["city"] is not None:
                    print("Ciudad: ", match["location"]["city"])
                if match["location"]["country_name"] is not None:
                    print("País: ", match["location"]["country_name"])
            if match["ip_str"] is not None:
                print("Host: ", match["ip_str"])
            print("\n")
    except Exception as e:
        logging.error("Ha ocurrido un error: " + str(e))
        return ("Ha ocurrido un error: " + str(e))
def PowerShell(ruta):
    try:
        lineaPS = "powershell -Executionpolicy ByPass -File Hash.ps1 -TargetFolder "+ ruta
        runningProcesses = subprocess.check_output(lineaPS)
        print("Archivo generado con los datos: baseline.txt")
    except Exception as e:
        logging.error("Ha ocurrido un error: " + str(e))
        return ("Ha ocurrido un error: " + str(e))
