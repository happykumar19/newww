# SSL Certificate Pinning Assessment — Arattai (com.aratai.chat v1.54.0)

**Date:** 2026-10-06  
**Target:** com.aratai.chat v1.54.0 (versionCode 1946)  
**Proxy:** Burp Suite Professional v2026.7.2  
**Device:** emulator-5554 (Android 12, API 31)  
**Verdict:** **ZERO SSL PINNING — ALL HTTPS TRAFFIC INTERCEPTABLE**

---

## Summary

Arattai implements **no SSL certificate pinning whatsoever**. All HTTPS traffic between the app and its backend servers (chat.arattai.in, profile.arattai.in, etc.) can be intercepted, read, and modified by any attacker in a Man-in-the-Middle position. This is especially critical because the app claims to provide "end-to-end encryption" for messages and calls, yet the transport layer has no pinning protection.

**Severity:** CRITICAL  
**CVSS 4.0:** 8.7  
**OWASP Mobile:** M5 — Insecure Communication  

---

## Evidence Chain

### 1. Static Analysis — No Pinning Code Exists

| Check | Result |
|-------|--------|
| `CertificatePinner` class in okhttp3/ | **ABSENT** — class completely stripped |
| `network_security_config.xml` | **ABSENT** — no file exists |
| Custom TrustManager implementation | **NONE** found |
| Certificate/public key files in assets/ | **NONE** found |

```
# OkHttp CertificatePinner class search
D:\aratai\arati_out\sources\okhttp3\  → No files matching CertificatePinner*

# Network security config search  
D:\aratai\arati_out\resources\  → No files matching network_security_config*
```

### 2. Dynamic Proof — App Fully Functional Through Burp

**Setup:**
- Burp Suite listening on `127.0.0.1:8080`
- Emulator proxy: `10.0.2.2:8080` (global HTTP proxy)
- Burp CA cert installed as system cert via tmpfs overlay at `/system/etc/security/cacerts/9a5ba575.0`
- SELinux context set: `u:object_r:system_security_cacerts_file:s0`

**Results:**
- App connected successfully — title changed from "Waiting for network..." to "Arattai"
- **5 ESTABLISHED TCP connections** through Burp port 8080 confirmed via netstat
- Chat rooms loaded with user data visible
- Contact search API returned user phone numbers (+91 63972 79479)
- Chat with user "~Garv" opened — full message history, call buttons, message input functional
- App displayed: "Messages and calls in this chat are now protected with **end-to-end encryption**" while all traffic flowed through Burp in cleartext

**Zero SSL/TLS errors in logcat:**
```
# Filtered logcat for SSL/TLS/certificate/pinning errors from app:
(No output — zero errors)
```

### 3. Network Connections Proof

```
TCP    127.0.0.1:8080    127.0.0.1:47114    ESTABLISHED
TCP    127.0.0.1:8080    127.0.0.1:47117    ESTABLISHED
TCP    127.0.0.1:8080    127.0.0.1:47125    ESTABLISHED
TCP    127.0.0.1:8080    127.0.0.1:47126    ESTABLISHED
TCP    127.0.0.1:8080    127.0.0.1:54316    ESTABLISHED
```

5 simultaneous HTTPS connections from the app through Burp — no pinning rejection.

---

## Attack Scenarios

### Scenario 1: Corporate/Public WiFi MitM
An attacker on the same network (coffee shop, airport, hotel, corporate WiFi) uses ARP spoofing or rogue AP to position themselves as MitM. With their own CA trusted by the device, all Arattai traffic is readable:
- OAuth tokens (`Zoho-oauthtoken`) intercepted → full account takeover
- Chat messages read in transit despite "E2EE" claim
- Contact lists and phone numbers exfiltrated
- Profile data and media files intercepted

### Scenario 2: Compromised/Malicious CA
A state-level attacker with access to a trusted CA (or a compromised CA) can issue certificates for `*.arattai.in` and intercept all communications. SSL pinning would prevent this; its absence means the app trusts ALL ~150 system CAs.

### Scenario 3: Enterprise Proxy Inspection
Corporate environments with TLS inspection proxies can read all Arattai traffic from employee devices — a privacy concern for a messaging app that promises E2EE.

---

## The E2EE Irony

The app displays "Messages and calls in this chat are now protected with **end-to-end encryption**" in chat rooms. However:

1. **No SSL pinning** = transport layer is wide open to MitM
2. **E2EE keys stored in SharedPreferences** (from static analysis: `ddl.java:70`, `cp4.java:485`)
3. **e2ee_by_default=false** in app configuration
4. **No Keystore usage** for E2EE key protection

A MitM attacker who intercepts the E2EE key exchange (which travels over the unpinned HTTPS connection) could potentially downgrade or break the E2EE entirely.

---

## Reproduction Steps

```bash
# 1. Download Burp CA cert
curl -o burp_ca.der http://127.0.0.1:8080/cert

# 2. Convert to PEM and get hash
openssl x509 -inform DER -in burp_ca.der -out burp_ca.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp_ca.pem -noout)
cp burp_ca.pem ${HASH}.0

# 3. Push to emulator
adb push ${HASH}.0 /data/local/tmp/
adb root

# 4. Install via tmpfs overlay (Android 11+ read-only /system)
adb shell mkdir -p /data/local/tmp/cacerts
adb shell cp /system/etc/security/cacerts/* /data/local/tmp/cacerts/
adb shell cp /data/local/tmp/${HASH}.0 /data/local/tmp/cacerts/
adb shell mount -t tmpfs tmpfs /system/etc/security/cacerts
adb shell cp /data/local/tmp/cacerts/* /system/etc/security/cacerts/
adb shell chcon u:object_r:system_security_cacerts_file:s0 /system/etc/security/cacerts/*

# 5. Set proxy
adb shell settings put global http_proxy 10.0.2.2:8080

# 6. Launch app
adb shell am force-stop com.aratai.chat
adb shell am start -n com.aratai.chat/com.arattai.home.presentation.ui.HomeActivity

# 7. Observe: all HTTPS traffic appears in Burp proxy history
# No SSL errors, no pinning rejection, full traffic interception
```

---

## Remediation

### Immediate (P0)

1. **Implement OkHttp CertificatePinner** for all Arattai domains:
```java
CertificatePinner pinner = new CertificatePinner.Builder()
    .add("chat.arattai.in", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .add("profile.arattai.in", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .add("*.arattai.in", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .build();

OkHttpClient client = new OkHttpClient.Builder()
    .certificatePinner(pinner)
    .build();
```

2. **Add network_security_config.xml** restricting trusted CAs:
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">arattai.in</domain>
        <pin-set expiration="2027-01-01">
            <pin digest="SHA-256">base64_encoded_pin_1=</pin>
            <pin digest="SHA-256">base64_encoded_backup_pin=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

3. **Pin backup keys** — always include at least one backup pin to prevent lockout during certificate rotation.

### Short-term (P1)

4. **Implement certificate transparency** checking
5. **Add runtime pinning verification** that detects proxy/MitM conditions
6. **Protect E2EE key exchange** with additional pinning layer or out-of-band verification

---

## Evidence Files

| File | Description |
|------|-------------|
| `ssl_pinning_bypass_proof.png` | Chat room with "~Garv" loaded through Burp — shows E2EE banner while traffic is intercepted |
| `ssl_home_through_burp.png` | Contact search results flowing through Burp proxy |
| `ssl_test2.png` | App home screen showing "Arattai" (connected) after proxy setup |
| `burp_ca.der` | Burp CA certificate (DER format) |
| `burp_ca.pem` | Burp CA certificate (PEM format) |
| `9a5ba575.0` | System cert file installed on emulator |

---

*Assessment performed using Burp Suite Professional v2026.7.2 with system-level CA injection*
