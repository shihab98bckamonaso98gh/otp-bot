import asyncio
import html
import logging
import os
import re
import time
import traceback
from datetime import datetime, timedelta
from typing import Optional

import requests
from dotenv import load_dotenv
from telegram import Bot
from telegram.error import RetryAfter, TimedOut

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("sms_otp_bot")

# ════════════════════════════════════════════════════════════════
#  CONFIGURATION – everything from .env
# ════════════════════════════════════════════════════════════════
TOKEN = os.getenv("BOT_TOKEN")
GROUP_CHAT_ID = os.getenv("GROUP_CHAT_ID")
try:
    GROUP_CHAT_ID_INT = int(GROUP_CHAT_ID) if GROUP_CHAT_ID else None
except ValueError:
    GROUP_CHAT_ID_INT = None

DATA_DIR = os.getenv("DATA_DIR", "/data")
os.makedirs(DATA_DIR, exist_ok=True)
SEEN_PAIRS_FILE = os.path.join(DATA_DIR, "seen_pairs_site8.txt")

SITE8_BASE_URL = os.getenv("SITE8_BASE_URL", "http://139.99.68.231/ints")
SITE8_USERNAME = os.getenv("SITE8_USERNAME", "")
SITE8_PASSWORD = os.getenv("SITE8_PASSWORD", "")
IDLE_INTERVAL = int(os.getenv("IDLE_INTERVAL", "3"))

RETRY_BACKOFF = 15
MAX_BACKOFF = 120
REQUEST_TIMEOUT = 60

session8 = requests.Session()
session8.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": f"{SITE8_BASE_URL}/agent/SMSCDRReports",
    "X-Requested-With": "XMLHttpRequest",
    "Connection": "close",
})

message_queue = asyncio.Queue()


# ════════════════════════════════════════════════════════════════
#  HELPERS
# ════════════════════════════════════════════════════════════════
def h(s):
    return html.escape(str(s), quote=False)


def mask_number(num):
    if not num or not num.strip():
        return "Unknown"
    num = num.strip()
    if not num.startswith("+"):
        num = "+" + num
    if len(num) <= 7:
        return num[:3] + "***"
    return num[:4] + "*" * (len(num) - 7) + num[-3:]


def load_seen_pairs(filename):
    if not os.path.exists(filename):
        return set()
    with open(filename, 'r') as f:
        return set(line.strip() for line in f if "|" in line)


def save_seen_pair(filename, number, otp):
    with open(filename, 'a') as f:
        f.write(f"{number}|{otp}\n")


def save_seen_pairs_bulk(filename, pairs):
    """Write multiple pairs at once – used only during initialisation."""
    with open(filename, 'w') as f:
        for number, otp in pairs:
            f.write(f"{number}|{otp}\n")


def extract_otp(sms_text: str) -> Optional[str]:
    if not isinstance(sms_text, str):
        return None
    s = sms_text.strip()
    if not s:
        return None
    m = re.search(r"#\s*((?:\d+\s*)+?)\s*is\s+your", s)
    if m:
        return re.sub(r"\s+", "", m.group(1))
    m = re.search(r"#\s*(\d[\d\s]+)", s)
    if m:
        return re.sub(r"\s+", "", m.group(1))
    keyword_patterns = [
        r"(?:cod[ée]?\s*(?:igo|e)?|code|otp|pin|password|verification|seguridad|código|kode|token)\s*(?:[:#-]?\s*)(\d{4,8})",
        r"(\d{4,8})\s*(?:is your|is het|es tu|je|is uw|es)\s*(?:code|otp|pin|password|verification)",
        r"code\s*[:#-]?\s*(\d{4,8})",
        r"otp\s*[:#-]?\s*(\d{4,8})",
        r"verification\s*code\s*[:#-]?\s*(\d{4,8})",
        r"security\s*code\s*[:#-]?\s*(\d{4,8})",
        r"2fa\s*code\s*[:#-]?\s*(\d{4,8})",
        r"(\d{4,8})\s*(?:コード|验证码|인증번호)",
        r"código\s*[:#-]?\s*(\d{4,8})",
        r"cod\s*de\s*seguridad\s*[:#-]?\s*(\d{4,8})",
        r"cod\s*de\s*seguridad\s*(\d{4,8})",
        r"tu\s*código\s*es\s*(\d{4,8})",
    ]
    for pat in keyword_patterns:
        m = re.search(pat, s, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    if re.fullmatch(r"\d{4,8}", s):
        return s
    matches = re.findall(r"\b\d{4,8}\b", s)
    if matches:
        valid = [num for num in matches if not (num.startswith('0') and len(num) >= 10)]
        if valid:
            return valid[-1]
    return None


# ════════════════════════════════════════════════════════════════
#  SITE LOGIN & FETCH
# ════════════════════════════════════════════════════════════════
def site_login(session, base_url, username, password, retries=3):
    login_url = f"{base_url}/login"
    signin_url = f"{base_url}/signin"
    for _ in range(retries):
        try:
            resp = session.get(login_url, timeout=REQUEST_TIMEOUT)
        except Exception:
            time.sleep(2)
            continue
        match = re.search(r"What is (\d+)\s*\+\s*(\d+)\s*=\s*\?\s*:", resp.text)
        if not match:
            time.sleep(2)
            continue
        a, b = int(match.group(1)), int(match.group(2))
        answer = a + b
        data = {"username": username, "password": password, "capt": str(answer)}
        try:
            resp = session.post(signin_url, data=data, allow_redirects=True, timeout=REQUEST_TIMEOUT)
        except Exception:
            time.sleep(2)
            continue
        if "Dashboard" in resp.text or "/agent/" in resp.url:
            try:
                session.get(f"{base_url}/agent/", timeout=REQUEST_TIMEOUT)
            except Exception:
                pass
            return True
        time.sleep(2)
    return False


def fetch_data_sync(session, base_url):
    today = datetime.now()
    fdate1 = (today - timedelta(days=30)).strftime("%Y-%m-%d 00:00:00")
    fdate2 = (today + timedelta(days=1)).strftime("%Y-%m-%d 23:59:59")
    data_url = f"{base_url}/agent/res/data_smscdr.php"
    params = {
        "fdate1": fdate1,
        "fdate2": fdate2,
        "frange": "",
        "fclient": "",
        "fnum": "",
        "fcli": "",
        "fgdate": "",
        "fgmonth": "",
        "fgrange": "",
        "fgclient": "",
        "fgnumber": "",
        "fgcli": "",
        "fg": "0",
        "sEcho": "1",
        "iDisplayStart": "0",
        "iDisplayLength": "-1",
        "iColumns": "9",
        "sColumns": "",
        **{f"mDataProp_{i}": str(i) for i in range(9)},
    }
    for _ in range(3):
        try:
            resp = session.get(data_url, params=params, timeout=REQUEST_TIMEOUT)
        except Exception:
            time.sleep(2)
            continue
        if "login" in resp.url.lower():
            return None
        if resp.status_code != 200:
            time.sleep(2)
            continue
        try:
            json_data = resp.json()
        except Exception:
            if "login" in resp.text.lower() and "password" in resp.text.lower():
                return None
            time.sleep(2)
            continue
        rows = json_data.get("aaData")
        return rows if rows is not None else []
    return None


async def fetch_data_async(session, base_url):
    return await asyncio.to_thread(fetch_data_sync, session, base_url)


# ════════════════════════════════════════════════════════════════
#  INITIAL SEED – record all existing OTPs silently
# ════════════════════════════════════════════════════════════════
async def initialize_seen_pairs(session, base_url, seen_file):
    """Fetch current data once and save all number|otp pairs so we never resend them."""
    rows = await fetch_data_async(session, base_url)
    if not rows:
        logger.warning("Could not fetch initial data – will start from empty seen set.")
        return

    pairs = set()
    for row in rows:
        if len(row) < 9:
            continue
        sms_text = str(row[5])
        otp = extract_otp(sms_text)
        if not otp:
            continue
        number = str(row[2]).strip()
        pairs.add((number, otp))

    if pairs:
        save_seen_pairs_bulk(seen_file, pairs)
        logger.info(f"Pre‑loaded {len(pairs)} existing OTPs into seen file.")
    else:
        logger.info("No existing OTPs found during initialisation.")


# ════════════════════════════════════════════════════════════════
#  MESSAGE WORKER (sequential, rate‑limited)
# ════════════════════════════════════════════════════════════════
async def message_worker(bot: Bot):
    while True:
        row, otp = await message_queue.get()
        try:
            await send_single_otp(bot, row, otp)
        except Exception as e:
            logger.error(f"Worker error: {e}")
        finally:
            message_queue.task_done()
        await asyncio.sleep(3.5)   # safe gap between messages


async def send_single_otp(bot: Bot, row, otp: str, max_retries=5):
    if not GROUP_CHAT_ID_INT:
        return
    number = str(row[2]).strip()
    cli = str(row[3]).strip() if len(row) > 3 else ""
    sms = str(row[5]).strip() if len(row) > 5 else ""
    masked = mask_number(number)
    text = (
        f"✅ 📩 <b>Message Received!</b>\n\n"
        f"🏢 CLI : {h(cli)}\n"
        f"📞 Number: {masked}\n\n"
        f"🔑 OTP: {h(otp)}\n\n"
        f"💬 Message:\n{h(sms)}"
    )
    for attempt in range(1, max_retries + 1):
        try:
            await bot.send_message(
                chat_id=GROUP_CHAT_ID_INT,
                text=text,
                parse_mode="HTML",
                read_timeout=30,
                write_timeout=30,
            )
            return
        except RetryAfter as e:
            wait = e.retry_after + 1
            logger.warning(f"Flood control – waiting {wait}s")
            await asyncio.sleep(wait)
        except TimedOut:
            logger.warning(f"Timed out (attempt {attempt})")
            await asyncio.sleep(5)
        except Exception as e:
            logger.error(f"Send error: {e}")
            await asyncio.sleep(5)
    logger.error(f"Failed to send OTP {otp} after {max_retries} attempts")


# ════════════════════════════════════════════════════════════════
#  MAIN SCRAPER LOOP
# ════════════════════════════════════════════════════════════════
async def monitor_site8(bot: Bot):
    session = session8
    base_url = SITE8_BASE_URL
    username = SITE8_USERNAME
    password = SITE8_PASSWORD
    seen_file = SEEN_PAIRS_FILE
    idle = IDLE_INTERVAL

    # Login
    if not site_login(session, base_url, username, password):
        logger.error("Initial login failed – will retry in loop")

    # **Only** send new OTPs: first load all currently existing pairs silently
    if not os.path.exists(seen_file) or os.path.getsize(seen_file) == 0:
        logger.info("Seeding seen pairs with existing data (no messages will be sent)...")
        await initialize_seen_pairs(session, base_url, seen_file)

    seen_pairs = load_seen_pairs(seen_file)
    consecutive_failures = 0

    while True:
        rows = await fetch_data_async(session, base_url)
        if rows is None:
            if site_login(session, base_url, username, password):
                rows = await fetch_data_async(session, base_url)
                if rows is not None:
                    consecutive_failures = 0
                else:
                    consecutive_failures += 1
            else:
                consecutive_failures += 1
            backoff = min(RETRY_BACKOFF * (consecutive_failures + 1), MAX_BACKOFF)
            await asyncio.sleep(backoff)
            continue
        else:
            consecutive_failures = 0

        new_data_found = False
        for row in rows:
            if len(row) < 9:
                continue
            sms_text = str(row[5])
            otp = extract_otp(sms_text)
            if not otp:
                continue
            number = str(row[2]).strip()
            pair = f"{number}|{otp}"
            if pair in seen_pairs:
                continue
            new_data_found = True
            seen_pairs.add(pair)
            save_seen_pair(seen_file, number, otp)
            await message_queue.put((row, otp))

        # Dynamic speed
        if new_data_found:
            await asyncio.sleep(0.1)   # instant refetch
        else:
            await asyncio.sleep(idle)


async def safe_monitor(bot: Bot):
    while True:
        try:
            await monitor_site8(bot)
        except Exception:
            logger.error(f"Monitor crashed: {traceback.format_exc()}")
            await asyncio.sleep(60)


async def main_async():
    if not TOKEN:
        logger.critical("BOT_TOKEN missing.")
        return

    async with Bot(TOKEN) as bot:
        logger.info("Bot started – initialising and then monitoring for new OTPs.")
        await asyncio.gather(
            message_worker(bot),
            safe_monitor(bot),
        )


if __name__ == "__main__":
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        logger.info("Stopped by user.")