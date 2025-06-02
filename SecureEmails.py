import os.path
import base64
import re
import filetype
import threading
import requests
import argparse
from datetime import datetime
from time import sleep
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

"""
  ACLARACIONES: 

    Google permite que apps de escritorio usen client secret, sin que sean un secreto, no comprometiendo absolutamente nada como en este caso particular https://developers.google.com/identity/protocols/oauth2?hl=es-419#installed debido a que es sabido que no los pueden mantener (se pueden utilizar tecnicas de analisis forense para )
    Para las apps de escritorio se utiliza PKCE (Proof Key for Code Exchange) como capa extra de seguridad, sin embargo por temas de velocidad en el desarollo, presindi de ese flujo de autorización.

    Es totalmente necesario aclarar que las variables utilizadas como publicas hardcodeadas en este caso son una mala practica, se puede extrapolar a un file de entorno o del mismo sistema, sin embargo por temas de practicidad fueron puestas ahi,

    Las KEYS (Publicas y privadas) son de cuentas de prueba, debido a que esto es un challenge por temas de practicidad y velocidad de desarollo las comparto para que se pueda ejecutar el script, en un entorno de produccion esto no se hace, serán eliminadas posteriormente de la entrega del challenge

  DOCUMENTACION: 

    Documentacion de filetype, encargado de revisar el tipo de archivo mediante su magic number( que determina que tipo de extension posee para que pueda leerse): https://pypi.org/project/filetype/

    Documentacion sobre el manejo de hilos en python: https://docs.python.org/es/3.8/library/threading.html documentacion para hilos

    Documentacion del agregado de parametros mediante CLI (parser): https://docs.python.org/3/library/argparse.html#module-argparse

    Documentacion sobre las partes de un Mail https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages?hl=es-419#Message.MessagePart
"""

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
  """
  Permite crear el flujo de autenticación de OAuth, y otorgandonos las credenciales.
  """
  client_config = {
        "installed": {
            "client_id": PUBLIC_KEY,
            "client_secret": CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"]
        }
  }
  flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
  creds = flow.run_local_server(port=0)
  return creds

def decode_body_message(payload):
  """
  obtiene los mensajes del cuerpo de un mail buscandolos y decodificandolos
  Documentacion del cuerpo: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages?hl=es-419#Message.MessagePart  

  Parámetros:
        payload (object (MessagePart)): La estructura del correo electrónico analizada en las partes del mensaje.
  """
  
  if "parts" in payload:
      for part in payload["parts"]:
          if (part["mimeType"] == "text/plain" or "text/html") and "data" in part["body"]:
              return base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")

  if "body" in payload and "data" in payload["body"]:
      return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8")

  return "body can not be redeable"

def search_words(text):
  """
  Permite buscar palabras de CRITICAL_WORDS dentro del texto pasado.

  Parámetros:
        text (string).
  """
  word = text.lower().split()
  for w in word:
    matches_critical = [critical for critical in CRITICAL_WORDS if re.search(rf"\b{re.escape(critical)}\b", w)]
    if matches_critical: return matches_critical[0]
  return None

def get_message_critical_word(header, sender, critical_word):
  """
  Permite crear un mensaje de palabra critica encontrada

  Parámetros:
        header (string): encabezado del mensaje.
        sender (string): de quien proviene el mensaje.
        critical_word (string): palabra critica encontrada.
  """
  if not header: header="\"No subject\""
  message = ("Critical word -"+ critical_word + "- from " + sender + " on email with subject " + header)
  return message

def file_handler_alert(warning_message):
  """
  Manejada la funcionalidad del archivo donde se escribirá dado una alerta de palabra critica.
  Documentacion de funcionalidad de file https://www.w3schools.com/python/python_file_open.asp

  Parámetros:
        warning_message (string): mensaje de alerta.
  """
  with open("alertas.txt", "a") as f:
    f.write("\n"+warning_message)
    f.close()

def send_notification_to_server(warning_message,url,port):
  """
  Funcion encargada de envio de mensajes al servidor.
  Documentacion de request para manejo de envios al servidor: https://requests.readthedocs.io/en/latest/ 
  Parámetros:
        warning_message (string): mensaje de alerta.
        url (string): url del servidor.
        port (string): puerto de envio al servidor.
  """
  final_url = url+":"+port
  warning_message = warning_message+" - Date registered at " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  requests.post(final_url, json={"Log:":warning_message})

def email_secure(email):
  """
  Funcion encargada de verificar si el mail esta anotado como seguro en la withelist.

  Parámetros:
        email (string): mail a verificar.
  """
  mail_accepted = [mail for mail in WHITELIST_ENTERPRISE if re.search(rf"@{re.escape(mail)}.com$", email)]
  if mail_accepted: return True
  return False

def get_file_from_body(body,service,mail_id):
  """
  Permite obtener el los datos decodificados del archivo, recibiendo el body del mail.

  Parámetros:
        body (object (MessagePartBody)): Body del Mail.
        service (build("gmail", "v1", credentials=creds)): Servicio que permite comunicarse con Gmail API.
        mail_id (string): Id del mail.
  """
  if "data" in body:
    data = body["data"]
  elif "attachmentId" in body:
    attachment = service.users().messages().attachments().get(userId="me",messageId=mail_id,id=body["attachmentId"]).execute()
    data = attachment["data"]
  file_data = base64.urlsafe_b64decode(data.encode("UTF-8"))
  return file_data

def detect_extension(file_data, filename):
  """
  Detecta la extensión de un archivo:
  Usa filetype (magic bytes).
  Si falla, inspecciona firmas simples.
  Por ultimo revisa el nombre del archivo.
  Retorna la extensión o 'unknown'.
  """
  file_type = filetype.guess(file_data)
  if file_type: return file_type.extension.lower()
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
  if filename:
    file_type = os.path.splitext(filename)[1].lower().lstrip('.')
    if file_type: return file_type

  return 'unknown'

def check_attach(payload, header,sender,virustotal,service,mail_id):
  """
  Funcion encargada de chequear los adjuntos de los mails, verificando si son seguros contra VirusTotal si la flag esta activa y reportandolos en el log.
  Documentacion sobre attachment del Mail https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages?hl=es-419#Message.MessagePart
  Parámetros:
        payload (object (MessagePart)): La estructura del correo electrónico analizada en las partes del mensaje.
        header (string): encabezado del mensaje.
        sender (string): de quien proviene el mensaje.
        virustotal (Bool): Activa verificacion contra VirusTotal del file.
        service (build("gmail", "v1", credentials=creds)): Servicio que permite comunicarse con Gmail API.
        mail_id (string): Id del mail.
  """
  if "parts" in payload:
    for part in payload["parts"]:
      if not part["filename"]: continue
      file_data = get_file_from_body(part["body"],service,mail_id)
      filename = part["filename"]
      file_type = detect_extension(file_data, filename)
      if file_type.lower() in CRITICAL_EXTENSIONS:
        file_handler_alert("File with extension "+file_type+" found on email from "+sender+" with subject"+header)
        if virustotal:
          hilo_vt = threading.Thread(
                        target=hilo_viruscheck_and_inform_log,
                        args=(file_data, file_type, sender, header))
          hilo_vt.start()

def hilo_viruscheck_and_inform_log(file_data, file_type, sender, header):
  """
  Funcion que maneja funcionamiento del hilo encargada de comprobar que el archivo sea seguro contra VirusTotal y informar lso resultados en el log.

  Parámetros:
        file_data (bytes): Bytes del archivo.
        file_type (string): Tipo del archivo.
        header (string): Encabezado del mensaje.
        sender (string): De quien proviene el mensaje.
  """
  result = virustotal_check(file_data) 
  file_handler_alert("VIRUSTOTAL RESULT ->"+ result +" from file with extension "+file_type+" found on email from "+sender+" with subject"+header )

def virustotal_check(file_data):
  """
  Funcion encargada de comprobar que el archivo sea seguro contra VirusTotal mediante su API.
  Documentacion de VirusTotal API https://docs.virustotal.com/reference/files-scan 
  Parámetros:
        file_data (bytes): Bytes del archivo.
  """
  files = {"file": ("file", file_data)}
  headers = {"x-apikey": KEY_VIRUSTOTAL}
  response = requests.post(URL_TO_UPLOAD_FILE,files=files,headers=headers)
  
  if response.status_code != 200:
    print("Error uploading file attachment:", response.text)
    return "upload_failed"
  else:
    id_analysis = response.json()["data"]["id"]

  sleep(15) 

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

  parser = argparse.ArgumentParser()
  parser.add_argument("--revise", help="amount of emails to revise", type=int) 
  parser.add_argument("--virustotal", help="this tag avilable virustotal scan", action="store_true") 
  parser.add_argument("--url", help="url to send notification", type=str) 
  parser.add_argument("--port", help="port to send notification", type=str) 

  args = parser.parse_args()
  amount_emails = args.revise or 5 
  url = args.url or "http://127.0.0.1"
  port = args.port or str(5555)
  virustotal = args.virustotal 

  try:
    service = build("gmail", "v1", credentials=creds)
    emails_list = service.users().messages().list(userId="me", maxResults = amount_emails ).execute()
    emails = emails_list.get("messages", [])

    if not emails:
      print("No emails")
      exit
    for mail in emails:
      mail_id = mail["id"]
      message = service.users().messages().get(userId="me", id=mail_id).execute()
      sender = next(part["value"] for part in message["payload"]["headers"] if part["name"] == "From")
      if( not email_secure(sender) ):
        header = next(part["value"] for part in message["payload"]["headers"] if part["name"] == "Subject")
        body_message = decode_body_message(message["payload"])
        critical_word = search_words(header) or search_words(body_message)
        if critical_word:
          warning_message = get_message_critical_word(header, sender, critical_word)
          print(warning_message)
          file_handler_alert(warning_message)
          send_notification_to_server(warning_message,url,port)

        check_attach(message["payload"], header,sender,virustotal,service,mail_id)

  except HttpError as error:
    print(f"An error occurred: {error}")

if __name__ == "__main__":
  main()