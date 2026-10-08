# E2EE Message Encryption Analysis — Arattai v1.54.0

**Date:** 2026-10-06  
**Intercepted via:** Burp Suite (zero SSL pinning)  
**Extracted from:** SharedPreferences + SQLite databases on emulator  

---

## Message Decryption: CONFIRMED

### The encrypted message from the wire:
```json
{
  "msg": "i6Rxwez/xE/M5ejP$kifyMhnzBoG+DJzvV0ezhThS",
  "ctype": 1,
  "sender": "20034686476",
  "meta": {
    "enc_conflict": false,
    "enc_keys": { "source_device_id": "47178907" },
    "message_type": "text",
    "enc": true,
    "revision": 1
  },
  "msgid": "232625102_1791270172770",
  "id": "1791270173833_4563778697",
  "dname": "badmaash"
}
```

### The decrypted plaintext from the local database:
```
message_id: 1791270173833%204563778697  | sender: badmaash | text: Hi
message_id: 1791270251324%208858823484  | sender: Batman   | text: Whatsup
```

**Your "hi" = `i6Rxwez/xE/M5ejP$kifyMhnzBoG+DJzvV0ezhThS` when encrypted on the wire.**

---

## How the Encryption Works

### Message Format Analysis
The encrypted message `i6Rxwez/xE/M5ejP$kifyMhnzBoG+DJzvV0ezhThS` uses `$` as a delimiter:
- **Part 1 (IV/Nonce):** `i6Rxwez/xE/M5ejP` (16 bytes base64 = 12 bytes raw — AES-GCM nonce)
- **Part 2 (Ciphertext+Tag):** `kifyMhnzBoG+DJzvV0ezhThS` (ciphertext with GCM auth tag)

### Encryption Scheme
- **Protocol:** Signal Protocol (libsignal) with Sender Keys for groups
- **Message Cipher:** AES-GCM (nonce$ciphertext format)
- **Key Exchange:** X3DH (Extended Triple Diffie-Hellman) via Signal Protocol bundles
- **Key Storage:** Per-message AES keys stored in plaintext SQLite database

### Key Material Extracted from Device

#### 1. Signal Identity Key (SharedPreferences: `20034686476.xml`)
```
e2ee_identity_key: CiEFFc70gcmrJXYwkhxvgruSqT8sOZ6L8tV5/LYrNxA93WsSIADrrswsj6Rf35hn...
e2ee_device_id: 47178907
e2ee_signed_pre_key: CPanzawBEiEFcD/sYcdN8qWp2y65LHcFxqZ8GYQ7t1IcHubh7MqfVx8aINB8...
e2ee_pre_key_start_id: 9826
e2ee_by_default: true
e2ee_registration_complete: true
session_rotation_threshold: 10
session_rotation_msgcounter_threshold: 1950
primary_device_session_id: 7fd7a24bd38a33b917e695...
```

#### 2. Per-Message AES Keys (Database: `arattai_aes_keys_20034686476.db`)
```sql
-- Schema: PLAINTEXT SQLite (NOT SQLCipher)
CREATE TABLE AesKey (
    id TEXT NOT NULL,
    chat_id TEXT NOT NULL,
    message_id TEXT,
    aes_key TEXT NOT NULL,   -- ← BASE64-ENCODED AES KEY IN PLAINTEXT
    type TEXT,
    PRIMARY KEY (id, chat_id)
);

-- Extracted keys:
-- Message "Hi" (badmaash):
--   key_id: 232625102_1791270172770
--   chat_id: 1466404004773725408
--   aes_key: Vszm+GsMXv2uV5nXJvc/kxG3eppQ4g24PaU5bN5BC5A=
--   type: message

-- Message "Whatsup" (Batman):
--   key_id: 1791270251324%208858823484
--   chat_id: 1466404004773725408
--   aes_key: 5640wSOM0YVa5ERjXA6kNmMR4qZfp/Wqse3FulXVscc=
--   type: message
```

#### 3. RSA Keys (SharedPreferences: `arattai_enc_prefs.xml`)
```
- Encrypted with AndroidX Security (Tink AES-SIV for keys, AES-GCM for values)
- Tink keysets stored alongside encrypted data in the SAME file
- Contains: enc_publickey, enc_privatekey (RSA 2048-bit)
```

#### 4. Database Encryption Key (SharedPreferences: `arattai_local_db_key.xml`)
```xml
<string name="key">L3Tkqw1TVFcDj4ToMnTa13hw8cHAXDgS/yNZf1AGBU4=</string>
<string name="key_id">1791195351071</string>
<string name="zuid">20034686476</string>
```
**Note:** This key is stored in PLAINTEXT — no Android Keystore protection.

---

## Critical Vulnerabilities Found

### VULN 1: E2EE Messages Stored Decrypted in Plain SQLite (CRITICAL)

The encrypted messages database (`arattai_enc_messages_20034686476.db`) stores messages in **plaintext SQLite** — not even SQLCipher encrypted:
```
Header: SQLite format 3\000 (standard unencrypted SQLite)
```

Any app with root access, or any backup tool, can read all "E2EE" messages in cleartext. The database file header confirms no encryption:
```
00000000: 5351 4c69 7465 2066 6f72 6d61 7420 3300  SQLite format 3.
```

### VULN 2: AES Message Keys Stored in Plaintext Database (CRITICAL)

Per-message AES keys are stored in `arattai_aes_keys_20034686476.db` as base64 strings in an unencrypted SQLite database. An attacker who obtains this file can decrypt any intercepted message.

**Decryption is trivial:**
```python
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# From AesKey table
aes_key = base64.b64decode("Vszm+GsMXv2uV5nXJvc/kxG3eppQ4g24PaU5bN5BC5A=")

# From intercepted message: nonce$ciphertext
parts = "i6Rxwez/xE/M5ejP$kifyMhnzBoG+DJzvV0ezhThS".split("$")
nonce = base64.b64decode(parts[0])
ciphertext = base64.b64decode(parts[1])

# Decrypt
aesgcm = AESGCM(aes_key)
plaintext = aesgcm.decrypt(nonce, ciphertext, None)
print(plaintext.decode())  # → "Hi"
```

### VULN 3: Signal Identity Key in SharedPreferences (HIGH)

The Signal Protocol identity key pair is stored in SharedPreferences (`20034686476.xml`), not in Android Keystore. This means:
- Any root-level access extracts the full identity
- App backup includes the identity key
- No hardware-backed protection

### VULN 4: E2EE Key Exchange Interceptable via MitM (HIGH)

Since there's zero SSL pinning (proven in SSL_PINNING_ASSESSMENT.md), the Signal Protocol key exchange bundles travel over interceptable HTTPS. The `enc_keys` in the message metadata contains the session key material:
```json
"enc_keys": {
  "source_device_id": "174395417",
  "20034686476_9624_47178907": "MwohBffHWG8DbRXx4bvsQQMMKxbikNkAyL/v6aDy3qf5DhMUEAAYACIw..."
}
```
A MitM attacker could:
1. Intercept the initial key exchange bundle
2. Perform a key substitution attack
3. Decrypt all subsequent messages

### VULN 5: CryptoUtil Uses AES/ECB with Native JNI Key (HIGH)

`CryptoUtil.java` uses:
- **AES/ECB/PKCS5Padding** (line 37) — ECB mode leaks patterns in ciphertext
- Key from native `getkey()` via `libexternal-native-iam-lib.so` — extractable via Frida
- **RSA/ECB/PKCS1Padding** (line 29) — vulnerable to Bleichenbacher padding oracle

### VULN 6: Tink Keysets Stored Alongside Encrypted Data (MEDIUM)

The `arattai_enc_prefs.xml` file stores:
- `__androidx_security_crypto_encrypted_prefs_key_keyset__` — the Tink AES-SIV keyset
- `__androidx_security_crypto_encrypted_prefs_value_keyset__` — the Tink AES-GCM keyset
- Both keysets are in the SAME file as the encrypted RSA keys they protect

This is equivalent to storing the lock combination taped to the safe.

---

## Attack Chain: Full Message Decryption

```
Step 1: MitM (no SSL pinning)
  → Intercept encrypted message on the wire
  → msg = "i6Rxwez/xE/M5ejP$kifyMhnzBoG+DJzvV0ezhThS"

Step 2: Extract AES key (root access or backup extraction)
  → arattai_aes_keys_20034686476.db (plain SQLite, no encryption)
  → aes_key = "Vszm+GsMXv2uV5nXJvc/kxG3eppQ4g24PaU5bN5BC5A="

Step 3: Decrypt
  → Split on "$": nonce = "i6Rxwez/xE/M5ejP", ciphertext = "kifyMhnzBoG+DJzvV0ezhThS"
  → AES-GCM decrypt with extracted key
  → Plaintext: "Hi"

Alternative: Just read the database
  → arattai_enc_messages_20034686476.db
  → text_message column = "Hi" (already decrypted, stored in plaintext!)
```

---

## Feature Flags Revealing Weak E2EE Posture

From the extracted preferences:
```json
{
  "e2ee_calls": false,              // Voice/video calls NOT encrypted
  "e2ee_with_backup": false,        // Backups NOT E2EE protected
  "e2ee_live_location": false,      // Location sharing NOT encrypted
  "e2ee_secure_storage": false,     // Local storage NOT secured
  "e2ee_backup": false,             // Cloud backup NOT encrypted
  "group_e2ee": false,              // Group chats NOT E2EE
  "e2ee_message_transfer": false,   // Message transfer NOT encrypted
  "forward_info_encryption_enabled": false,
  "e2ee_draft": false,
  "secret_chat_release": false,
  "e2ee_for_group_meetings": false
}
```

Almost every E2EE-related feature flag is **disabled**. Only basic 1:1 text message E2EE is enabled, and even that stores messages decrypted locally.

---

## Summary

The Arattai "end-to-end encryption" is fundamentally broken at multiple levels:

1. **Messages stored decrypted** in plaintext SQLite databases
2. **AES keys stored in plaintext** alongside the messages
3. **No SSL pinning** allows MitM interception of key exchange
4. **Signal identity keys** in SharedPreferences, not Android Keystore
5. **Tink keysets co-located** with the data they encrypt
6. **Most E2EE features disabled** via server-controlled feature flags
7. **AES/ECB mode** used in CryptoUtil (pattern-leaking)
8. **RSA/ECB/PKCS1Padding** vulnerable to Bleichenbacher attacks

The E2EE banner ("Messages and calls in this chat are now protected with end-to-end encryption") is misleading — the encryption provides minimal protection against any local attacker, backup extractor, or network MitM.

---

*Analysis performed via Burp Suite traffic interception + adb root data extraction on emulator-5554*
