import os.path # permite obtener el path, os es del sistema operativo.
import base64
from datetime import datetime
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# aclaracion Google permite que apps de escritorio usen client secret, sin que sean un secreto, no comprometiendo absolutamente nada en este caso particular https://developers.google.com/identity/protocols/oauth2?hl=es-419#installed

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
PUBLIC_KEY = "1017525713366-jkriu4gsfepugq0livovv6ntfsiqndop.apps.googleusercontent.com"
CLIENT_SECRET = "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"

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
          if part["mimeType"] == "text/plain" and "data" in part["body"]:
              return base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
      # Si no encontró texto plano, busca HTML
      for part in payload["parts"]:
          if part["mimeType"] == "text/html" and "data" in part["body"]:
              return base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
    
  # 2: Mensaje simple (sin partes, version de email simple sin formato)
  if "body" in payload and "data" in payload["body"]:
      return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8")
    
  return "body can not be redeable"

def search_words(text):
  critical_words = ["contraseña","confidencial"]
  word = text.split()
  for w in word:
    if w in critical_words:
      return w
  return None

def get_message_critical_word(header, sender, critical_word):
  return ("\nCritical word "+ critical_word + " from " + sender + " on email with subject " + header  + "  - Date registered at "+ datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

def file_handler_alert(warning_message):
  #mas manejo del file https://www.w3schools.com/python/python_file_open.asp
  #lo abrimos con "a" para posicionarnos al final del archivo, ya que al escribir sobrescribe encima si estoy al incio.
  with open("alertas.txt", "a") as f:
    f.write(warning_message)
    f.close()

def main():
  creds = get_creds()

  try:
    #llamado al gmail API, creando el servicio con las credenciales de OAuth
    service = build("gmail", "v1", credentials=creds)
    #listado de mensajes
    emails_list = service.users().messages().list(userId="me", maxResults = 5).execute()
    emails = emails_list.get("messages", [])

    if not emails:
      print("No emails")
      exit
    for mail in emails:
      # para cada mensaje tenemos sus componentes https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages?hl=es-419#Message.MessagePart

      # ESTRUCTURA GMAIL (VERSIÓN ARBOL)
      #message -> 
      #  id: str               # Ej: "18a2d8f3e4b5c7"
      #  snippet: str          # Vista previa ("Hola...")
      #  payload ->
      #      headers ->         # METADATOS
      #        name: FROM | TO | SUBJECT | DATE  # (Siempre strings)
      #        value: str     # Ej: "user@mail.com" o "Asunto importante"
      #      body? ->           # CUERPO SIMPLE (si no hay parts)
      #        data: Base64    # Texto plano/HTML codificado
      #       parts? ->          # PARTES (si es multipart/adjuntos)
      #        mimeType: TEXT/PLAIN | TEXT/HTML | IMAGE/JPEG | APPLICATION/PDF
      #        body -> data: Base64  # Contenido (o attachmentId si es adjunto)
      #        filename?: str  # Para adjuntos (ej: "doc.pdf")

      message = service.users().messages().get(userId="me", id=mail["id"]).execute()
      # next obtiene el siguiente valor que cumpla condicion | generator expression devuelve una lista part de value
      header = next(part["value"] for part in message["payload"]["headers"] if part["name"] == "Subject")
      body_message = decode_body_message(message["payload"])

      #busco la palabra clave y la intento guardar, en cuyo caso sera None, sino disparo el handler
      critical_word = search_words(header) or search_words(body_message)
      if critical_word:
        #lo coloco acá para no hacer proceso extra en caso de no ser necesario
        sender = next(part["value"] for part in message["payload"]["headers"] if part["name"] == "From")
        warning_message = get_message_critical_word(header, sender, critical_word)
        file_handler_alert(warning_message)
        print(warning_message) 

      if message["payload"]["filename"]: print("Adjunto:", message["payload"]["filename"][0])

  except HttpError as error:
    print(f"An error occurred: {error}")

if __name__ == "__main__":
  main()