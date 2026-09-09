import os
import requests
from dotenv import load_dotenv

load_dotenv()

token = os.getenv("TELEGRAM_BOT_TOKEN")
chat_id = os.getenv("TELEGRAM_CHAT_ID")

print("Token present :", bool(token))
print("Chat ID :", repr(chat_id))

url = f"https://api.telegram.org/bot{token}/sendMessage"
r = requests.post(url, data={"chat_id": chat_id, "text": "TEST direct depuis test_telegram.py"}, timeout=15)

print("Status :", r.status_code)
print("Reponse Telegram :", r.text)