# generate.py
from flask import Flask, request, jsonify
import json
import os
import time
import random
import base64
import hmac
import hashlib
import requests
from urllib3.exceptions import InsecureRequestWarning
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import codecs
import re
from datetime import datetime

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# === Configuration ===
REGION_LANG = {
    "ME": "ar", "IND": "hi", "ID": "id", "VN": "vi", "TH": "th",
    "BD": "bn", "PK": "ur", "TW": "zh", "CIS": "ru", "SAC": "es", "BR": "pt"
}

hex_key = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
key = bytes.fromhex(hex_key)
GARENA = "QkxBQ0tfQVBJcw=="  # "BLACK_APIs" in base64

# Rarity threshold
RARITY_SCORE_THRESHOLD = 3

# --- Utility Functions (kept same as before) ---
def generate_random_name(base_name):
    exponent_digits = {'0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹'}
    number = random.randint(1, 99999)
    number_str = f"{number:05d}"
    exponent_str = ''.join(exponent_digits[digit] for digit in number_str)
    return f"{base_name[:7]}{exponent_str}"

def generate_custom_password(prefix):
    garena_decoded = base64.b64decode(GARENA).decode('utf-8')
    characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    random_part1 = ''.join(random.choice(characters) for _ in range(5))
    random_part2 = ''.join(random.choice(characters) for _ in range(5))
    return f"{prefix}_{random_part1}_{garena_decoded}_{random_part2}"

def EnC_Vr(N):
    if N < 0: return b''
    H = []
    while True:
        BesTo = N & 0x7F
        N >>= 7
        if N: BesTo |= 0x80
        H.append(BesTo)
        if not N: break
    return bytes(H)

def CrEaTe_VarianT(field_number, value):
    field_header = (field_number << 3) | 0
    return EnC_Vr(field_header) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value

def CrEaTe_ProTo(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(CrEaTe_LenGTh(field, value))
    return packet

def E_AEs(Pc):
    Z = bytes.fromhex(Pc)
    aes_key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(Z, AES.block_size))

def encrypt_api(plain_text):
    plain_bytes = bytes.fromhex(plain_text)
    aes_key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plain_bytes, AES.block_size))
    return ct.hex()

def decode_jwt_token(jwt_token):
    try:
        parts = jwt_token.split('.')
        if len(parts) >= 2:
            payload_part = parts[1]
            padding = 4 - len(payload_part) % 4
            if padding != 4:
                payload_part += '=' * padding
            decoded = base64.urlsafe_b64decode(payload_part)
            data = json.loads(decoded)
            return str(data.get('account_id') or data.get('external_id', 'N/A'))
    except Exception as e:
        print(f"JWT decode error: {e}")
    return "N/A"

def check_account_rarity(account_data):
    account_id = account_data.get("account_id", "")
    if not account_id or account_id == "N/A":
        return False, 0, ""

    score = 0
    reasons = []

    patterns = {
        "REPEATED_DIGITS_4": [r"(\d)\1{3,}", 3],
        "SEQUENTIAL_5": [r"(12345|23456|34567|45678|56789)", 4],
        "PALINDROME_6": [r"^(\d)(\d)(\d)\3\2\1$", 5],
        "SPECIAL_COMBINATIONS_HIGH": [r"(69|420|1337|007)", 4],
        "QUADRUPLE_DIGITS": [r"(1111|2222|3333|4444|5555|6666|7777|8888|9999|0000)", 4],
        "GOLDEN_RATIO": [r"1618|0618", 3]
    }

    for pattern_name, (pattern, pts) in patterns.items():
        if re.search(pattern, account_id):
            score += pts
            reasons.append(pattern_name)

    is_rare = score >= RARITY_SCORE_THRESHOLD
    return is_rare, score, ", ".join(reasons) if is_rare else ""

# --- Account Generator Class ---
class FreeFireAccountGenerator:
    def create_acc(self, region, name_prefix, password_prefix, is_ghost=False):
        password = generate_custom_password(password_prefix)
        data = f"password={password}&client_type=2&source=2&app_id=100067"
        signature = hmac.new(key, data.encode(), hashlib.sha256).hexdigest()

        headers = {
            "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
            "Authorization": "Signature " + signature,
            "Content-Type": "application/x-www-form-urlencoded"
        }

        try:
            resp = requests.post(
                "https://100067.connect.garena.com/oauth/guest/register",
                headers=headers, data=data, timeout=10, verify=False
            )
            if resp.status_code == 200 and 'uid' in resp.json():
                uid = resp.json()['uid']
                time.sleep(0.5)
                return self.token(uid, password, region, name_prefix, password_prefix, is_ghost)
        except Exception as e:
            print(f"Create account error: {e}")
        return None

    def token(self, uid, password, region, name_prefix, password_prefix, is_ghost):
        body = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": key,
            "client_id": "100067"
        }
        try:
            resp = requests.post(
                "https://100067.connect.garena.com/oauth/guest/token/grant",
                data=body, timeout=10, verify=False
            )
            if resp.status_code == 200 and 'open_id' in resp.json():
                open_id = resp.json()['open_id']
                access_token = resp.json()['access_token']
                field = self.encode_field_14(open_id)
                return self.Major_Regsiter(access_token, open_id, field, uid, password, region, name_prefix, password_prefix, is_ghost)
        except Exception as e:
            print(f"Token error: {e}")
        return None

    def encode_field_14(self, open_id):
        keystream = [0x30] * 32
        encoded = ''.join(chr(ord(c) ^ keystream[i % 32]) for i, c in enumerate(open_id))
        return codecs.decode(''.join(f'\\u{ord(c):04x}' if ord(c) > 126 else c for c in encoded), 'unicode_escape').encode('latin1')

    def Major_Regsiter(self, access_token, open_id, field, uid, password, region, name_prefix, password_prefix, is_ghost):
        name = generate_random_name(name_prefix)
        url = "https://loginbp.ggblueshark.com/MajorRegister"
        lang = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")

        payload = {
            1: name,
            2: access_token,
            3: open_id,
            5: 102000007,
            6: 4,
            7: 1,
            13: 1,
            14: field,
            15: lang,
            16: 1,
            17: 1
        }

        payload_bytes = CrEaTe_ProTo(payload)
        encrypted_payload = E_AEs(payload_bytes.hex())

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "Authorization": "Bearer"
        }

        try:
            resp = requests.post(url, headers=headers, data=encrypted_payload, timeout=10, verify=False)
            if resp.status_code == 200:
                login_result = self.perform_major_login(uid, password, access_token, open_id, region, is_ghost)
                account_id = login_result.get("account_id", "N/A")
                jwt_token = login_result.get("jwt_token", "")
                return {
                    "uid": uid,
                    "password": password,
                    "name": name,
                    "region": "GHOST" if is_ghost else region,
                    "account_id": account_id,
                    "jwt_token": jwt_token
                }
        except Exception as e:
            print(f"MajorRegister error: {e}")
        return None

    def perform_major_login(self, uid, password, access_token, open_id, region, is_ghost):
        lang = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
        payload_parts = [
            b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
            lang.encode("ascii"),
            b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        ]
        payload = b''.join(payload_parts)
        payload = payload.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
        payload = payload.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())

        encrypted = encrypt_api(payload.hex())
        final_payload = bytes.fromhex(encrypted)

        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Bearer"}

        try:
            resp = requests.post(url, headers=headers, data=final_payload, timeout=10, verify=False)
            if resp.status_code == 200:
                text = resp.text
                jwt_start = text.find("eyJ")
                if jwt_start != -1:
                    jwt = text[jwt_start:]
                    dot2 = jwt.find(".", jwt.find(".") + 1)
                    if dot2 != -1:
                        jwt = jwt[:dot2 + 44]
                        acc_id = decode_jwt_token(jwt)
                        return {"account_id": acc_id, "jwt_token": jwt}
        except Exception as e:
            print(f"Login error: {e}")
        return {"account_id": "N/A", "jwt_token": ""}

# === Flask App ===
app = Flask(__name__)

@app.route('/generate', methods=['POST'])
def generate_accounts():
    if request.method != 'POST':
        return jsonify({"error": "Only POST allowed"}), 405

    try:
        body = request.get_json()
    except:
        return jsonify({"error": "Invalid JSON"}), 400

    region = body.get("region", "BR")
    count = min(int(body.get("count", 1)), 10)  # Max 10 per request
    name_prefix = body.get("name", "BLACK_Apis")
    password_prefix = body.get("password", "FF2024")
    is_ghost = body.get("ghost", False)

    if is_ghost:
        region = "BR"

    generator = FreeFireAccountGenerator()
    results = []

    for _ in range(count):
        account = generator.create_acc(region, name_prefix, password_prefix, is_ghost)
        if account:
            is_rare, score, reason = check_account_rarity(account)
            account["rare"] = is_rare
            account["rarity_score"] = score
            account["rarity_reason"] = reason
            results.append(account)
        time.sleep(1)

    return jsonify({
        "success": True,
        "count": len(results),
        "accounts": results,
        "timestamp": datetime.now().isoformat()
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})

# Vercel requires handler to export `app`
# But Vercel Python builder automatically handles Flask
# Just make sure file is named `generate.py` and route is `/generate`

# Nothing else needed!
