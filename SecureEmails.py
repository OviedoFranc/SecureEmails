import os.path # permite obtener el path, os es del sistema operativo.

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# aclaracion Google permite que apps de escritorio usen client secret, sin que sean un secreto, no comprometiendo absolutamente nada en este caso particular https://developers.google.com/identity/protocols/oauth2?hl=es-419#installed

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
PUBLIC_KEY = '1017525713366-jkriu4gsfepugq0livovv6ntfsiqndop.apps.googleusercontent.com'
CLIENT_SECRET = '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'

def getCreds():
  client_config = {
        "installed": {
            "client_id": PUBLIC_KEY,
            "client_secret": CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"]
        }
  }
  #esta parte se encarga de crear el flujo de autenticacion, abriendo el navegador para que entremos con nuestra cuenta de google
  flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
  creds = flow.run_local_server(port=0)
  return creds

def main():
  creds = getCreds()

  try:
    #llamado al gmail API, creando el servicio con las credenciales de OAuth
    service = build("gmail", "v1", credentials=creds)
    #listado de mensajes
    message_list = service.users().messages().list(userId="me", maxResults = 5).execute()
    messages = message_list.get("messages", [])

    if not messages:
      print("No messages")
    else:
      for msg in messages:
        message = service.users().messages().get(userId="me", id=msg["id"]).execute()
        print(message)

  except HttpError as error:
    print(f"An error occurred: {error}")

if __name__ == "__main__":
  main()