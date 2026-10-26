import asyncio
import html
import json
import os
from datetime import timedelta
from dotenv import load_dotenv
from telegram import Bot
from telegram.error import BadRequest, NetworkError, RetryAfter, TelegramError, TimedOut

load_dotenv()

bot_token = os.getenv("BOT_TOKEN")
allowed_user_ids = list(map(int, os.getenv("USERS").split(',')))
attacks = os.getenv("ATTACK_IDS", "").split(',')
ignore_list = os.getenv("IGNORED_ATTACK_IDS", "").split(',')
priorities = os.getenv("PRIORITY", "").split(',')

LOG_FILE = "/var/log/suricata/eve.json"
POLL_INTERVAL = 0.5
MAX_SEND_ATTEMPTS = 3

async def send_telegram_message(user_id, message):
    """Sends a Telegram message. Never raises, so a failed send can't stop monitoring."""
    bot = Bot(token=bot_token)
    parse_mode = 'HTML'
    for attempt in range(1, MAX_SEND_ATTEMPTS + 1):
        try:
            await bot.send_message(chat_id=user_id, text=message, parse_mode=parse_mode)
            return
        except RetryAfter as e:
            delay = e.retry_after
            if isinstance(delay, timedelta):
                delay = delay.total_seconds()
            print(f"Error: Telegram rate limit hit for user {user_id}, retrying in {delay}s.")
            await asyncio.sleep(delay)
        except BadRequest as e:
            if parse_mode is None:
                print(f"Error: Telegram rejected message for user {user_id}. Exception: {e}")
                return
            # Shouldn't happen since fields are escaped, but never drop an alert over formatting.
            print(f"Error: HTML rejected for user {user_id}, resending as plain text. Exception: {e}")
            parse_mode = None
        except TimedOut as e:
            print(f"Error: Telegram message send timed out for user {user_id}. Exception: {e}")
        except NetworkError as e:
            print(f"Error: Network error sending to user {user_id}. Exception: {e}")
            await asyncio.sleep(1)
        except TelegramError as e:
            print(f"Error: Telegram error sending to user {user_id}. Exception: {e}")
            return
    print(f"Error: Giving up on message for user {user_id} after {MAX_SEND_ATTEMPTS} attempts.")

class LogTailer:
    """Follows a log file like `tail -F`: returns only new lines, survives rotation and truncation."""

    def __init__(self, path):
        self.path = path
        self.file = None
        self.inode = None
        self.buffer = b""
        # Skip what's already in the log at startup; only alert on new events.
        self._open(seek_end=True)

    def _open(self, seek_end):
        try:
            self.file = open(self.path, "rb")
        except FileNotFoundError:
            return False
        if seek_end:
            self.file.seek(0, os.SEEK_END)
        self.inode = os.fstat(self.file.fileno()).st_ino
        self.buffer = b""
        return True

    def _read_available(self):
        data = self.file.read()
        if not data:
            return []
        lines = (self.buffer + data).split(b"\n")
        # Last element is an incomplete line (or empty); finish it on a later read.
        self.buffer = lines.pop()
        return [line.decode("utf-8", errors="replace") for line in lines]

    def _rotated(self):
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            # Moved away, new file not created yet; keep reading the old one.
            return False
        return st.st_ino != self.inode or st.st_size < self.file.tell()

    def read_lines(self):
        if self.file is None and not self._open(seek_end=False):
            return []
        lines = self._read_available()
        if self._rotated():
            # Old file is drained above; switch to the new one from its start.
            if self.buffer:
                lines.append(self.buffer.decode("utf-8", errors="replace"))
            self.file.close()
            self.file = None
            if self._open(seek_end=False):
                lines += self._read_available()
        return lines

def format_endpoint(ip, port):
    return f"{ip}:{port}" if port is not None else str(ip)

def format_alert(title, event):
    alert = event["alert"]
    src = format_endpoint(event.get("src_ip"), event.get("src_port"))
    dest = format_endpoint(event.get("dest_ip"), event.get("dest_port"))
    fields = [
        ("Signature", html.escape(alert.get("signature", ""))),
        ("SID", f"<code>{alert['signature_id']}</code>"),
        ("Category", html.escape(alert.get("category", ""))),
        ("Flow", f"<code>{html.escape(src)} → {html.escape(dest)}</code> ({html.escape(event.get('proto', '?'))})"),
        ("Action", html.escape(alert.get("action", ""))),
        ("Time", html.escape(event.get("timestamp", ""))),
    ]
    return f"<b>{title}</b>\n" + "\n".join(f"<b>{name}:</b> {value}" for name, value in fields if value)

async def process_line(line):
    try:
        event = json.loads(line)
    except ValueError:
        return
    if not isinstance(event, dict) or event.get("event_type") != "alert":
        return
    alert = event.get("alert", {})
    if "signature_id" not in alert:
        return
    attack_id = str(alert["signature_id"])
    if attack_id in ignore_list:
        return

    # eve.json "severity" is the rule priority shown as [Priority: N] in fast.log.
    priority_value = alert.get("severity")
    if priorities != [''] and priority_value and str(priority_value) in priorities:
        message = format_alert(f"HIGH PRIORITY EVENT (Priority {priority_value}) DETECTED", event)
    elif attacks != [''] and attack_id in attacks:
        message = format_alert("NEW ATTACK DETECTED", event)
    else:
        return

    for user_id in allowed_user_ids:
        await send_telegram_message(user_id, message)

async def main() -> None:
    """Main function to monitor logs and send alerts."""
    tailer = LogTailer(LOG_FILE)
    print("Alerting is enabled. Monitoring for attacks...")
    for user_id in allowed_user_ids:
        await send_telegram_message(user_id, "Alerting enabled. Monitoring for attacks...")
    while True:
        for line in tailer.read_lines():
            await process_line(line)
        await asyncio.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    asyncio.run(main())
