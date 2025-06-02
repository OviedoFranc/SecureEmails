import os.path # permite obtener el path, os es del sistema operativo.
import base64
import re
import filetype
import threading #https://docs.python.org/es/3.8/library/threading.html documentacion para hilos
import requests
import argparse
from datetime import datetime
from time import sleep
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# aclaracion Google permite que apps de escritorio usen client secret, sin que sean un secreto, no comprometiendo absolutamente nada en este caso particular https://developers.google.com/identity/protocols/oauth2?hl=es-419#installed

# aclaracion 2: es cierto que esto es totalmente una mala practica tener variables hardcodeadas y no en entorno, se encuentran acá a modo de rapido desarollo, las mismas son completamente de prueba y serán eliminadas posteriormente de la entrega del challenge
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
PUBLIC_KEY = "1017525713366-jkriu4gsfepugq0livovv6ntfsiqndop.apps.googleusercontent.com"
CLIENT_SECRET = "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"
WHITELIST_ENTERPRISE = ["google, empresa"]
CRITICAL_WORDS = ["contraseña","confidencial"]
CRITICAL_EXTENSIONS = ["exe","zip","js","bat"]
KEY_VIRUSTOTAL = "17d89b932de59a64dd7198279bf563137ec2a6029155e4141b99d4590623c0ce"
URL_TO_UPLOAD_FILE = "https://www.virustotal.com/api/v3/files"
URL_TO_GET_REPORT = "https://www.virustotal.com/api/v3/analyses/"

def get_creds():
  client_config = {
        "installed": {
            "client_id": PUBLIC_KEY,
            "client_secret": CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"]
        }
  }
  # esta parte se encarga de crear el flujo de autenticacion, abriendo el navegador para que entremos con nuestra cuenta de google
  flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
  creds = flow.run_local_server(port=0)
  return creds

def decode_body_message(payload):
  # https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages?hl=es-419#Message.MessagePart
  # todo codificado en base64url segun la documentacion
  # 1: Mensaje con partes (caso clasico cubre la mayoria | RFC 2822 es el formato de emails)
  # TEXT/PLAIN | TEXT/HTML | IMAGE/JPEG | APPLICATION/PDF 
  # el cuerpo del mensaje es "attachmentId": string (si posee un archivo adjunto), "size": integer, "data": string
  if "parts" in payload:
      for part in payload["parts"]:
          # Primero busca texto plano
          if (part["mimeType"] == "text/plain" or "text/html") and "data" in part["body"]:
              return base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
    
  # 2: Mensaje simple (sin partes, version de email simple sin formato)
  if "body" in payload and "data" in payload["body"]:
      return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8")
    
  return "body can not be redeable"

#funcion encargada de buscar las claves criticas
def search_words(text):
  #transformo todo el texto a minuscula y lo separo
  word = text.lower().split()
  for w in word:
    #usando comprension de lista
    #encierro entre \b \b para que ejemplo .contraseña: lo tome correctamente! ya que no siempre las cosas esta separadas por respectivos espacios
    # la otra es que uso re.escape para no tomar quizas simbolos como * o de regedex y que sean interpetados (regedex inyection) por lo tanto re.escape toma literalmente el string https://ssojet.com/compare-escaping/
    # r -> permite tomar el caracter como si fuera \caracter, tomandolo en crudo
    # f permite insertar {variable externa}
    matches_critical = [critical for critical in CRITICAL_WORDS if re.search(rf"\b{re.escape(critical)}\b", w)]
    if matches_critical: return matches_critical[0]
  return None

#creo los mensajes para despues usarlos donde los necesite
def get_message_critical_word(header, sender, critical_word):
  if not header: header="\"No subject\""
  message = ("Critical word -"+ critical_word + "- from " + sender + " on email with subject " + header)
  return message

def file_handler_alert(warning_message):
  #mas manejo de file https://www.w3schools.com/python/python_file_open.asp
  #lo abrimos con "a" para posicionarnos al final del archivo, ya que al escribir sobrescribe encima si estoy al incio.
  with open("alertas.txt", "a") as f:
    f.write("\n"+warning_message)
    f.close()

def send_notification_to_server(warning_message,url,port):
    #bonus, envio un post al servidor para que lo registre, no es indispensable para el funcionamiento
    final_url = url+":"+port
    warning_message = warning_message+" - Date registered at " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    #envio el mensaje como un json
    #documentacion para el apartado del request: https://requests.readthedocs.io/en/latest/ 
    requests.post(final_url, json={"Log:":warning_message})

def email_secure(email):
  #unicamente acepta empresas en la lista blanca, esto sucede debido a que Empresa no es igual a EMPRESA, quiza alguien se suplantacion de identidad con dicho metodo. 
  #la otra es que uso re.escape para no tomar quizas simbolos como * o de regedex y que sean interpetados (regedex inyection) por lo tanto re.escape toma literalmente el string https://ssojet.com/compare-escaping/
  # r -> permite tomar el caracter como si fuera \caracter, tomandolo en crudo
  # f permite insertar {variable externa}
  mail_accepted = [mail for mail in WHITELIST_ENTERPRISE if re.search(rf"@{re.escape(mail)}.com$", email)]
  if mail_accepted: return True
  return False

#existen dos casos posibles, si el archivo es muy grande attachmentId no se encuentra vacio y tiene un id del archivo
#si el archivo es pequeño, se guarda codificado dentro del data de body
def get_file_from_body(body,service,mail_id):
  if "data" in body:
    data = body["data"]
  elif "attachmentId" in body:
    attachment = service.users().messages().attachments().get(userId="me",messageId=mail_id,id=body["attachmentId"]).execute()
    data = attachment["data"]
  file_data = base64.urlsafe_b64decode(data.encode("UTF-8"))
  return file_data

#encargada de detectar la extension
def detect_extension(file_data, filename):
  #pruebo segun el magic   
  file_type = filetype.guess(file_data)
  if file_type: return file_type.extension.lower()
  #detecto segun firma (estilo magic)
  if file_data.startswith(b'MZ'):
    return 'exe'
  elif file_data.startswith(b'\x50\x4B\x03\x04'):
    return 'zip'
  elif file_data.strip().startswith(b'#!/bin/bash'):
    return 'sh'
  elif b'@echo off' in file_data.lower() or file_data.strip().startswith(b'cmd'):
    return 'bat'
  elif b'function' in file_data and b'document' in file_data:
    return 'js'
  #pruebo segun la extension
  if filename:
    file_type = os.path.splitext(filename)[1].lower().lstrip('.')
    if file_type: return file_type

  return 'unknown'

#funcion encarga de revisar los adjuntos en los emails
#documentacion del attch https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages?hl=es-419#Message.MessagePart
def check_attach(payload, header,sender,virustotal,service,mail_id):
  if "parts" in payload:
    for part in payload["parts"]:
      #si no encuentro nombre de archvio paso de largo (segun documentacion debe existir siempre, por eso si no lo tiene es que no tiene archivo adjunto)
      if not part["filename"]: continue
      #obtenemos la data del archivo
      file_data = get_file_from_body(part["body"],service,mail_id)
      #obtenemos el filename para enviarlo a la funcion en caso de no detectar firma
      filename = part["filename"]
      file_type = detect_extension(file_data, filename)
      #si encuentro que esta en la extensiones, mando un mensaje al handler de lo que encontre!
      if file_type.lower() in CRITICAL_EXTENSIONS:
        file_handler_alert("File with extension "+file_type+" found on email from "+sender+" with subject"+header)
        if virustotal:
          #procedo a abrir un hilo paralelo pora poder seguir verificando mails, la idea es no dejar en espera activa, el programa espera a que los hilos terminen
          hilo_vt = threading.Thread(
                        target=hilo_viruscheck_and_inform_log,
                        args=(file_data, file_type, sender, header))
          hilo_vt.start()

#esta funcion opcional se abre en un hilo paralelo, que comprueba que el archivo sea seguro y lo informa en los los dentro de alertas.txt
def hilo_viruscheck_and_inform_log(file_data, file_type, sender, header):
  result = virustotal_check(file_data) 
  file_handler_alert("VIRUSTOTAL RESULT ->"+ result +" from file with extension "+file_type+" found on email from "+sender+" with subject"+header )

#documentacion de virus total api https://docs.virustotal.com/reference/files-scan 
def virustotal_check(file_data):
  #envio de archivo a analizar
  files = {"file": ("file", file_data)}
  headers = {"x-apikey": KEY_VIRUSTOTAL}
  response = requests.post(URL_TO_UPLOAD_FILE,files=files,headers=headers)
  
  if response.status_code != 200:
    print("Error uploading file attachment:", response.text)
    return "upload_failed"
  else:
    #la api de virus total devuelve el id del analisis para comprobar posteriormente
    id_analysis = response.json()["data"]["id"]

  #el escaneo tarda, deberiamos hacer varios request pero por motivos practivos pongo un sleep, dejando en stand by este hilo
  sleep(15) 
  #comprobacion de resultados
  url = URL_TO_GET_REPORT + id_analysis
  headers = {"x-apikey": KEY_VIRUSTOTAL}
  result = requests.get(url, headers=headers)
  if result.status_code != 200:
    print("Error with report file attachment:", result.text)
    return "get_report_failed"
  attributes = result.json()["data"]["attributes"]
  stats = attributes.get("stats", {})

  if stats.get("malicious", 0) > 0:
    return "malicious"
  elif stats.get("suspicious", 0) > 0:
    return "suspicious"
  elif stats.get("harmless", 0) > 0 and stats.get("undetected", 0) > 0:
    return "probably harmless"
  else:
    return "undetected"

def main():
  creds = get_creds()

  #parser es para agregar parametros por CLI, permitiendonos obtener luego lo introducido, en este caso tenemos un por defecto de 5 si no fue especificado
  #pagina de la documentacion https://docs.python.org/3/library/argparse.html#module-argparse
  parser = argparse.ArgumentParser()
  parser.add_argument("--revise", help="amount of emails to revise", type=int) 
  #ek action lo vuelve true si pongo el parametro
  parser.add_argument("--virustotal", help="this tag avilable virustotal scan", action="store_true") 
  parser.add_argument("--url", help="url to send notification", type=str) 
  parser.add_argument("--port", help="port to send notification", type=str) 

  #asignacion de parametros,si no estan seteados pongo por defecto
  args = parser.parse_args()
  amount_emails = args.revise or 5 
  url = args.url or "http://127.0.0.1"
  port = args.port or str(5555)
  virustotal = args.virustotal 

  try:
    #llamado al gmail API, creando el servicio con las credenciales de OAuth
    service = build("gmail", "v1", credentials=creds)
    #listado de mensajes
    emails_list = service.users().messages().list(userId="me", maxResults = amount_emails ).execute()
    emails = emails_list.get("messages", [])

    if not emails:
      print("No emails")
      exit
    for mail in emails:
      # para cada mensaje tenemos sus componentes https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages?hl=es-419#Message.MessagePart
      mail_id = mail["id"]
      message = service.users().messages().get(userId="me", id=mail_id).execute()
      sender = next(part["value"] for part in message["payload"]["headers"] if part["name"] == "From")
      if( not email_secure(sender) ):
        header = next(part["value"] for part in message["payload"]["headers"] if part["name"] == "Subject")
        body_message = decode_body_message(message["payload"])
        #busco la palabra clave y la intento guardar, si existe disparo el handler para manejar la filtracion de la palabra,sino tendré un None.
        critical_word = search_words(header) or search_words(body_message)
        if critical_word:
          warning_message = get_message_critical_word(header, sender, critical_word)
          print(warning_message)
          file_handler_alert(warning_message)
          send_notification_to_server(warning_message,url,port)

        #parte de comprobacion de archivo adjunto
        check_attach(message["payload"], header,sender,virustotal,service,mail_id)

  except HttpError as error:
    print(f"An error occurred: {error}")

if __name__ == "__main__":
  main()