import argparse
import Funciones

if __name__ == "__main__":
    description = ''' Tareas de Ciberseguridad:
        + Para realizar el escaneo de puertos es necesario descargar un nmap
          como "Zenmap", e ingresar la IP a escanear con "target"

        Ejemplo de uso:

            - python PIA.py -modo p -target 127.0.0.1
        
        Para realizar un escaneo completo cambie el último octeto de la IP por
        un 0/24, ejemplo 127.0.0.1 ---> 127.0.0.0/24
        
            - python PIA.py -modo p -target 127.0.0.0/24
        
        + Para realizar el web scraping ingrese la url a la que se le va a hacer
          el scraping con "url" (la url debe incluir el http al principio)

        Ejemplo de uso:

            - python PIA.py -modo s -url https://www.google.es

        + Para realizar la revisión de encabezados ingrese la url a la que se
          le va realizar la revisión de encabezados con el parámetro "url"
          (la url debe incluir el http al principio)

        Ejemplo de uso:

            - python PIA.py -modo e -url https://www.google.es

        + Para obtener la información de los sockets de un host ingrese con el
          parámetro "modo" las letras si y el host al que se le va a sacar la
          información con el parámetro "host"

        Ejemplo de uso:

            - python PIA.py -modo si -host google.com

        + Para cifrar un mensaje ingrese con el parámetro "modo" las letras cm y
          el mensaje a cifrar con el parámetro "msj", opcionalmente se puede
          poner una clave (número) con el parámetro "clave", el cifrado sera
          Cesar y por default tendra clave 4

        Ejemplo de uso:

            - python PIA.py -modo cm -msj "Hola mundo"

            - python PIA.py -modo cm -msj "Hola mundo" -clave 8

        + Para obtener la metadata de imagenes ingrese con el parámetro "modo"
          las letras meta y el path en donde se encuentran las imagenes con el
          parámetro "path"

        Ejemplo de uso:

            - python PIA.py -modo meta -path "C:\\Users\\user1\\Pictures"

        + Para utilizar la API de Shodan ingrese con el parámetro "modo" las
          letras API, la API key con el parámetro "APIkey" y el término a buscar
          con el parámetro "search"

        Ejemplo de uso:

            - python PIA.py -modo API -APIkey 552779739992737728 -search "telmex"
            
        + Para realizar la busqueda de hash ingrese el parámetro "ruta", después se
          almacenará en el archivo baseline.txt el resultado

        Ejemplo de uso:

            - python PIA.py -modo hash -ruta "C:\\Windows\\System32\\drivers\\"
        '''

    parser = argparse.ArgumentParser(description='PIA de ciberseguridad',
                                     epilog=description,
                                    formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-modo", dest="modo",
                        choices=["p", "s", "e", "si", "cm", "meta", "API", "hash"],
                        help="Ingresa p para escanear puertos, s para "
                             "web scraping, e para revisión de encabezados, "
                             "si para información de sockets, cm para cifrado "
                             "de mensajes, meta para obtención de metadatos, "
                             "API para usar la API de Shodan, hash para saber"
                             "el hash de una ruta",
                        required=True)
    parser.add_argument("-target", dest="target",
                        help="Ingresa la IP para nmap")    
    parser.add_argument("-url", dest="url", help="Ingresa la url para hacer "
                                                 "scraping en imágenes")
    parser.add_argument("-host", dest="hostname",
                        help="Ingresa el host que desee revisar la "
                             "información de sockets")
    parser.add_argument("-msj", dest="mensaje",
                        help="Ingresa el mensaje a cifrar")
    parser.add_argument("-clave", dest="clave", default=4,
                        help="Ingresa la clave con la que va a cifrar (número)")
    parser.add_argument("-path", dest="path",
                        help="Ingresa el path en donde se encuentran las "
                             "imagenes para extraer metadata")
    parser.add_argument("-APIkey", dest="APIkey",
                        help="Ingresa tu API key del sitio Shodan")
    parser.add_argument("-search", dest="search",
                        help="Ingresa el termino a buscar en Shodan")
    parser.add_argument("-ruta", dest="rhash",
                        help="Ingresa la ruta para analizar el hash")
    params = parser.parse_args()
    try:
        if params.modo == "p":
            Funciones.scanPorts(params.target)
        if params.modo == "s":
            Funciones.scrapingImages(params.url)
            Funciones.scrapingPDF(params.url)
            Funciones.scrapingLinks(params.url)
        if params.modo == "e":
            Funciones.checkHeaders(params.url)
        if params.modo == "si":
            Funciones.socketInfo(params.hostname)
        if params.modo == "cm":
            if not params.mensaje:
                print("Ingrese un mensaje, vuelva a ejecutar")
                exit()
            Funciones.cifrado(params.mensaje, params.clave)
        if params.modo == "meta":
            if not params.path:
                print("Ingrese un path, vuelva a intentar")
                exit()
            Funciones.printMeta(params.path)
        if params.modo == "API":
            if not params.APIkey:
                print("Ingrese una API key, vuelva a intentar")
                exit()
            if not params.search:
                print("Ingrese un término a buscar, vuelva a intentar")
                exit()
            Funciones.API(params.APIkey, params.search)
        if params.modo == "hash":
            if not params.rhash:
                print("Ingrese la ruta para obtener Hash, vuelva a intentar")
                exit()
            Funciones.PowerShell(params.rhash)
    except Exception as e:
        print(e)
