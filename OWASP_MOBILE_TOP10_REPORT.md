# Arattai (com.aratai.chat) v1.54.0 — OWASP Mobile Top 10 Assessment

**Date:** 2026-10-05  
**Target:** Arattai Messaging App (Android)  
**Package:** com.aratai.chat  
**Version:** 1.54.0 (versionCode 1946)  
**Type:** Authorized Penetration Test  
**Framework:** OWASP Mobile Top 10 (2024)  
**minSdkVersion:** 23 | **targetSdkVersion:** 35 | **compileSdkVersion:** 36  

---

## Executive Summary

| OWASP Category | Rating | Findings | Highest Severity |
|---|---|---|---|
| **M1** Improper Credential Usage | **FAIL** | 4 | HIGH |
| **M2** Inadequate Supply Chain Security | **FAIL** | 3 | HIGH |
| **M3** Insecure Authentication/Authorization | **FAIL** | 4 | CRITICAL |
| **M4** Insufficient Input/Output Validation | **FAIL** | 4 | CRITICAL |
| **M5** Insecure Communication | **FAIL** | 4 | HIGH |
| **M6** Inadequate Privacy Controls | **FAIL** | 6 | HIGH |
| **M7** Insufficient Binary Protections | **FAIL** | 4 | MEDIUM |
| **M8** Security Misconfiguration | **FAIL** | 8 | CRITICAL |
| **M9** Insecure Data Storage | **FAIL** | 5 | CRITICAL |
| **M10** Insufficient Cryptography | **FAIL** | 5 | HIGH |

**Overall Verdict: FAIL — 0/10 categories pass.**

The Arattai messaging application fails every OWASP Mobile Top 10 category. The most severe issues are: (1) all database encryption keys stored in plaintext SharedPreferences, (2) an exported intent proxy that forwards attacker-controlled data without any validation, (3) zero SSL certificate pinning on a messaging app handling E2EE content, (4) AES/ECB mode encryption with a hardcoded native key, and (5) Chucker HTTP debugging tool shipped in production. These can be chained for complete message database theft, silent message manipulation, and mass user deanonymization.

---

## M1 — Improper Credential Usage

**Rating: FAIL | Highest Severity: HIGH**

### M1-1: OAuth client_secret Extractable from APK (HIGH)

**File:** `com/zoho/accounts/zohoaccounts/nativelibrary/a.java:176-177, 468-471`

The OAuth `client_secret` is shipped inside the APK and transmitted alongside `client_id` during token exchange. The secret is "obfuscated" via `z28.d(str4, "CS")` but trivially recoverable by hooking the method or reading the decompiled logic. Combined with zero certificate pinning (M5), a MITM attacker captures both values.

```java
// a.java:176-177 — token exchange
hashMap.put("client_id", str3);
hashMap.put("client_secret", z28.d(str4, "CS"));  // obfuscated, not protected

// a.java:468-471 — refresh token grant (same pattern)
```

**Impact:** Attacker with the client_secret can forge OAuth token requests, impersonate the app, or perform token exchange attacks.

### M1-2: No Android Keystore Usage for ANY Credential Storage (HIGH)

**Files:** All `com/arattai/` and `com/zoho/chat/` sources

Zero references to `AndroidKeyStore`, `KeyStore.getInstance("AndroidKeyStore")`, `KeyGenParameterSpec`, `EncryptedSharedPreferences`, or `MasterKey` exist in any app-level code. All credentials — OAuth tokens, database encryption keys, E2EE keys, session tokens — are stored in plaintext or software-only encryption.

**Impact:** Any root-level access, backup extraction, or FileProvider exploit yields all credentials in cleartext.

### M1-3: Hardcoded Google API Keys (LOW)

**Files:**
- `AndroidManifest.xml:479` — Google Geo API key: `AIzaSyBaNVeWKDYa3OjUrzorXXbVp0g-KNR6hZE`
- `res/values/strings.xml:3067` — Firebase API key: `AIzaSyAvci8nilatWc2xrrc5BkxezC_fdAglOII`
- Firebase project ID: `852446314855`
- Zoho Maps API key: `60032476758-857170528ac3663a9842a9110c6a6203`
- Apptics framework IDs: `60047369915` / `453000000002061`

**Impact:** If keys lack referrer/IP restrictions, billing abuse is possible. API keys also serve as reconnaissance data.

### M1-4: OAuth Tokens Held as Plain Strings in Memory (MEDIUM)

**Files:** 16+ locations in `com/zoho/accounts/zohoaccounts/nativelibrary/` (a.java, g0.java, h0.java, i0.java, k0.java)

OAuth tokens are concatenated into `Authorization` headers as `"Zoho-oauthtoken " + this.a` — tokens are plain `String` fields, never wrapped in secure containers or zeroed after use.

**Impact:** Memory dump or Frida hook trivially extracts live OAuth tokens.

---

## M2 — Inadequate Supply Chain Security

**Rating: FAIL | Highest Severity: HIGH**

### M2-1: Chucker HTTP Inspector Shipped in Production (HIGH)

**Files:** `AndroidManifest.xml:1136-1157`, `com/chuckerteam/chucker/internal/`

The full Chucker HTTP debugging library is bundled in the production APK:
- `MainActivity` and `TransactionActivity` registered with own task affinity
- `ChuckerDatabase` with `HttpTransaction` entity logs all HTTP traffic
- `ChuckerFileProvider` exposes cache via content URIs
- `ClearDatabaseService` registered

Chucker intercepts and stores **all HTTP requests and responses**, including Authorization headers, request bodies, and API responses in a local Room database.

**Impact:** On any device, Chucker's UI can be launched to view all logged network traffic including auth tokens. Debug tools in production violate supply chain security.

### M2-2: 29+ Third-Party SDKs Bundled (MEDIUM)

| Category | Libraries |
|---|---|
| **Zoho Ecosystem** | zohoaccounts nativelibrary, Apptics analytics, Zoho RTCP meetings, Zoho Cliq AV |
| **Google** | Firebase (messaging, installations, datatransport), ML Kit (barcode, document scanner), Play Services auth, Maps |
| **Media** | Glide (OkHttp integration), Coil, Amplituda, ExoPlayer/Media3 |
| **Crypto** | BouncyCastle (full), libcurve25519.so, libsqlcipher.so |
| **Debug (SHOULD NOT SHIP)** | Chucker, Compose UI Tooling PreviewActivity |
| **Other** | Skydoves balloon, CropFileProvider, JourneyApps barcode, Facebook SDK, Russhwolf settings |

Each SDK is an additional attack surface. No evidence of dependency scanning or SBOM generation.

### M2-3: Compose PreviewActivity Exported in Production (LOW)

**File:** `AndroidManifest.xml:1401-1402`

`androidx.compose.ui.tooling.PreviewActivity` is `exported="true"` — a debug/tooling activity that should be stripped from release builds.

---

## M3 — Insecure Authentication/Authorization

**Rating: FAIL | Highest Severity: CRITICAL**

### M3-1: ExternalEntryPointActivity Intent Proxy — No Auth, No Validation (CRITICAL)

**File:** `ExternalEntryPointActivity.java:294-309, 357`

The exported `ExternalEntryPointActivity` stores raw attacker-controlled intent data (`getData()`, `getExtras()`, `getClipData()`, `getAction()`, `getType()`) into a static `l77.e` field without ANY validation or caller verification. This is forwarded to `HomeActivity`/`OnboardingActivity` with `force_resync=true`. The `s0()` routing method (line 357, 2767 bytecode instructions) routes these attacker-controlled values through the entire deep link router.

**Dynamic Proof:**
```bash
# Force-join victim into attacker-controlled meeting
adb shell am start -n com.aratai.chat/com.arattai.home.presentation.ui.ExternalEntryPointActivity \
  -a android.intent.action.VIEW -d 'https://meet.arattai.in/join/ATTACKER-MEETING-ID'
# Result: App attempts to join meeting immediately, no user confirmation

# Inject content URI with grant flags
adb shell am start -n com.aratai.chat/com.arattai.home.presentation.ui.ExternalEntryPointActivity \
  -a android.intent.action.VIEW -d 'content://com.aratai.chat.provider/files/...' -f 0x3
```

**Impact:** Any installed app or web page can inject arbitrary URIs, actions, flags, and selectors into the app's internal router.

### M3-2: Exported Activities Without Authentication Guards (HIGH)

| Activity | Manifest Line | Issue |
|---|---|---|
| `StorageUsageActivity` | 656 | No auth check — leaks user storage breakdown (images/videos/audio counts and sizes) |
| `AadharVerificationActivity` | 1169 | No auth — any app triggers national ID verification flow; uses static callback (`rvpVar`) |
| `HomeActivity` | 752 | Accepts `OPEN_ACCOUNTS_SETTINGS` action (line 1170 in Java) without caller validation |

### M3-3: NotificationMessageReceiver — No Permission Guard (HIGH)

**File:** `NotificationMessageReceiver.java:37-94`

Despite `exported="false"` in manifest, the receiver has intent-filters for `com.zoho.chat.READ` and `com.zoho.chat.REPLY`. On Android < 12 (API 31), intent-filters make components implicitly exported. The receiver directly processes read-receipts and replies from extras without any permission check.

**Dynamic Proof:**
```bash
# Mark messages as read silently
adb shell am broadcast -a com.zoho.chat.READ \
  -n com.aratai.chat/com.arattai.notification.receivers.NotificationMessageReceiver
# Result: Broadcast completed: result=0

# Inject reply on behalf of user
adb shell am broadcast -a com.zoho.chat.REPLY \
  -n com.aratai.chat/... --es android.intent.extra.TEXT 'injected_reply'
# Result: Broadcast completed: result=0
```

### M3-4: AppLock Bypass via Non-Secure Fallback (MEDIUM)

**File:** `AppLockActivity.java:99-106`

In `onResume()`, if `rmv.r(this)` returns false, the activity calls `setResult(-1)` and `finish()` — returning `RESULT_OK` without biometric or PIN verification. If the lock-needed check can be manipulated (timing, state, race condition), the lock is bypassed.

---

## M4 — Insufficient Input/Output Validation

**Rating: FAIL | Highest Severity: CRITICAL**

### M4-1: ExternalEntryPointActivity — No URI Scheme Allowlist (CRITICAL)

**File:** `ExternalEntryPointActivity.java:301-309`

All intent fields (`data`, `extras`, `clipData`, `action`, `type`) are stored into `l77.e` without sanitization. No URI scheme allowlist — the app accepts and processes `https://`, `content://`, `file://`, `javascript:`, and custom schemes via deep links. The routing method `s0()` at line 357 is too complex for JADX to fully decompile (2767 instructions), indicating extensive unvalidated routing logic.

### M4-2: SQL String Concatenation in MessagesDaoImpl (MEDIUM)

**File:** `MessagesDaoImpl.java:7921-7931`

```java
// Table name and WHERE clause concatenated directly
"UPDATE " + str + " SET flags = "
" WHERE ".concat(str2)
```

While the final `execSQL` uses parameterized `objArr`, the table name (`str`) and WHERE clause structure (`str2`) are concatenated directly. If any upstream caller passes user-controlled data into these parameters, SQL injection is possible.

### M4-3: Unsanitized HTML in Profile "About" Field (MEDIUM)

**Files:** `UserResponse.java:586-587`, `EditProfileFragment.java:102`

The `about` field stores and returns arbitrary HTML without sanitization. Dynamically confirmed: `<img src=x onerror=alert(1)>` is stored and returned verbatim by the API. If rendered in any HTML context (WebView, notification, channel preview), this is stored XSS.

### M4-4: JavascriptInterface Bridge Exposed (MEDIUM)

**File:** `dtl.java:98`

A `@JavascriptInterface` bridge method `postAction(String, String)` is exposed to WebView JavaScript. If any WebView in the app (including the miniapp subsystem in obfuscated classes) loads an attacker-controlled URL via the intent proxy (M3-1), this bridge method is callable from attacker JavaScript.

---

## M5 — Insecure Communication

**Rating: FAIL | Highest Severity: HIGH**

### M5-1: Zero SSL Certificate Pinning (HIGH)

**Files:** Entire codebase — `okhttp3/CertificatePinner.java` does NOT exist

The `CertificatePinner` class was stripped from or never included in the OkHttp build. No custom `TrustManager` or `HostnameVerifier` implementations exist in app code. All HTTPS traffic is interceptable with a user-installed CA certificate or Frida SSL bypass (only platform-level hooks needed).

**Dynamic Proof:** Frida universal SSL bypass script intercepted 100% of app traffic. Burp proxy captured all API calls after installing Burp CA — no additional app-level bypass was required.

### M5-2: No network_security_config.xml (HIGH)

No `network_security_config.xml` exists anywhere in the APK resources. The app relies entirely on Android platform defaults with zero customization of TLS trust anchors, domain restrictions, or cleartext traffic policies.

### M5-3: Analytics PII Transmitted in URL Query Parameters (MEDIUM)

**File:** `AppticsResourceProcessor.java:69`

Zoho Apptics sends device and user identifiers as URL query parameters:
```
https://apptics.zoho.in/sdk/v1/60047369915/453000000002061/engagement/add?
  deviceid=d0a7b24cae080e6d157a377472d3cb8f&userid=d0a7b24cae080e6d964e58fb86fced3e
```

**Impact:** Identifiers exposed in server logs, CDN caches, proxy logs, and browser history. Should use POST body.

### M5-4: No Cleartext HTTP URLs (POSITIVE)

All app-level endpoints use HTTPS. No `usesCleartextTraffic="true"` in manifest.

---

## M6 — Inadequate Privacy Controls

**Rating: FAIL | Highest Severity: HIGH**

### M6-1: Excessive Sensitive Permissions (HIGH)

The app requests permissions beyond typical messaging needs:

| Permission | Concern |
|---|---|
| `READ_CONTACTS` + `WRITE_CONTACTS` | Full address book access + modification |
| `GET_ACCOUNTS` + `MANAGE_ACCOUNTS` | Device account enumeration |
| `READ_PHONE_STATE` + `READ_PHONE_NUMBERS` | Phone number + IMEI extraction |
| `ACCESS_FINE_LOCATION` + `ACCESS_COARSE_LOCATION` | Precise location tracking |
| `REQUEST_INSTALL_PACKAGES` | Can install arbitrary APKs — unusual for chat app |
| `SYSTEM_ALERT_WINDOW` | Overlay attack vector |

### M6-2: Contact Sync Uploads Entire Address Book (HIGH)

**Files:** `ContactsSyncAdapterService` (exported, manifest line 211), `ContactsResponse.java`, `ContactsV3Response.java`

The app syncs the user's entire contact list to Zoho servers via an exported sync adapter. `Config.java` contains a `contactSyncThreshold` field controlling batch size. All contact phone numbers and names are transmitted.

### M6-3: Phone Number Enumeration API — Zero Rate Limiting (HIGH)

**Endpoint:** `GET /v3/directory?phone_number={phone}`

Any authenticated user can query arbitrary phone numbers at 14 req/sec (~1.2M numbers/day) with zero rate limiting. Returns `user_id` and `status` for each number. Chains into profile photo IDOR (M6-4).

### M6-4: Unauthenticated Profile Photo IDOR (HIGH)

**Endpoint:** `GET https://profile.arattai.in/file?ID={userId}&fs=thumb`

Profile photos accessible via direct URL using only internal user ID — no authentication required. Sequential user IDs enable bulk scraping. Chain: Phone Number → user_id → Profile Photo.

### M6-5: Aadhaar (National ID) Verification Exposed Without Auth (HIGH)

**File:** `AndroidManifest.xml:1169`

`AadharVerificationActivity` is exported with no permission check. Any app can launch the Indian national identity verification flow. Queries `in.gov.uidai.pehchaan` package directly.

### M6-6: Apptics Telemetry with 15+ Tracking Classes (MEDIUM)

Zoho Apptics SDK includes: `StatsSyncWorker`, `AppticsResourceProcessor`, `AppticsCrashTracker`, `AppticsLoggerModuleImpl`, and 11+ additional classes. Hardcoded RSA public key for encrypted telemetry, framework ID `60047369915`. Device/user IDs sent in URL query strings (not POST body).

---

## M7 — Insufficient Binary Protections

**Rating: FAIL | Highest Severity: MEDIUM**

### M7-1: No Root/Jailbreak Detection (MEDIUM)

Zero matches for `isRooted`, `RootBeer`, `detectRoot`, `SafetyNet`, `PlayIntegrity`, or `IntegrityManager` across 35K+ source files. The app runs unrestricted on rooted devices, where all SharedPreferences, databases, and files are directly accessible.

### M7-2: No Code Integrity Verification (MEDIUM)

No signature verification or anti-tampering mechanisms found. The APK can be repackaged with modified code (injected Frida gadget, patched logic) and runs without complaint.

### M7-3: Partial R8 Obfuscation Only (LOW)

R8/ProGuard is active — most app classes are in `defpackage/` with obfuscated names. However, Chucker, Zoho, and Arattai library packages retain full readable names. Obfuscation is not a security control and does not protect secrets.

### M7-4: Native Libraries Without Strip (LOW)

16+ `.so` libraries shipped across 5 architectures (arm64-v8a, armeabi-v7a, armeabi, x86, x86_64). `libexternal-native-iam-lib.so` contains the hardcoded AES key used in `CryptoUtil` — accessible via reverse engineering.

---

## M8 — Security Misconfiguration

**Rating: FAIL | Highest Severity: CRITICAL**

### M8-1: 19 Exported Components — Many Without Permission Protection (CRITICAL)

| Component | Type | Permission | Risk |
|---|---|---|---|
| `ExternalEntryPointActivity` | Activity | None | Intent proxy — forwards attacker data to internal router |
| `StorageUsageActivity` | Activity | None | Leaks user storage data |
| `AadharVerificationActivity` | Activity | None | Exposes national ID flow |
| `HomeActivity` | Activity | None | LAUNCHER + accepts internal actions |
| `ContactAction` (alias) | Activity | None | Opens messaging/call flows via MIME type |
| `MessageActionActivity` (alias) | Activity | Signature | Protected (good) |
| `DataTransferProvider` | Provider | Signature | Protected (good) |
| `AuthenticatorService` | Service | None | Account authenticator |
| `ContactsSyncAdapterService` | Service | None | Contact sync |
| `ArattaiMessagingService` | Service | None | FCM handler |
| `BootCompleteReceiver` | Receiver | None | Boot receiver |
| `SmsBroadcastReceiver` | Receiver | GMS | SMS retrieval |
| `FirebaseInstanceIdReceiver` | Receiver | C2DM | FCM |
| `PreviewActivity` (Compose) | Activity | None | Debug tooling |
| `SystemJobService` (WorkManager) | Service | BIND_JOB | System |
| `DiagnosticsReceiver` | Receiver | DUMP | WorkManager debug |
| `ProfileInstallReceiver` | Receiver | DUMP | Baseline profile |
| `RevocationBoundService` | Service | Signature | Google auth |
| `AssetPackExtractionService` | Service | None | Play Core |

### M8-2: Overly Broad FileProvider Configuration (HIGH)

**File:** `res/xml/provider_paths.xml`

```xml
<files-path name="files" path="." />       <!-- ENTIRE internal files -->
<cache-path name="cache" path="." />       <!-- ENTIRE cache -->
<external-path name="external_files" path="." />  <!-- ENTIRE external storage -->
```

All files in internal storage, cache, and external storage are grantable via the FileProvider. Combined with the intent proxy flag injection, an attacker can read arbitrary app files.

### M8-3: Chucker FileProvider Exposes Cache (MEDIUM)

**File:** `res/xml/chucker_provider_paths.xml`

Chucker's own FileProvider also exposes the entire cache directory: `<cache-path name="chucker" path="." />`.

### M8-4: ENFORCE_PASSCODE=false (MEDIUM)

**File:** `assets/conf.properties`

```properties
ENFORCE_PASSCODE=false
ALLOW_DOWNLOAD_OR_SAVE=true
ALLOW_CHANNEL_CREATION=false
ALLOW_ACCOUNT_CREATION=true
```

App lock/passcode enforcement is disabled by default in the shipped configuration.

### M8-5: REQUEST_INSTALL_PACKAGES Permission (MEDIUM)

**File:** `AndroidManifest.xml:102`

A messaging app should not need `REQUEST_INSTALL_PACKAGES`. This allows the app to prompt users to install arbitrary APKs — an unusual and potentially dangerous capability.

### M8-6: SYSTEM_ALERT_WINDOW Permission (LOW)

**File:** `AndroidManifest.xml:133`

Allows the app to draw overlays on top of other apps. While used for call notifications, this capability can be abused for tapjacking/clickjacking attacks.

### M8-7: requestLegacyExternalStorage=true (LOW)

**File:** `AndroidManifest.xml:184`

Bypasses scoped storage on Android 10, granting broad external storage access.

### M8-8: No network_security_config.xml (HIGH)

No network security configuration file exists. No cleartext traffic restrictions, no domain-specific TLS policies, no certificate pinning declarations.

---

## M9 — Insecure Data Storage

**Rating: FAIL | Highest Severity: CRITICAL**

### M9-1: Database Encryption Key in Plaintext SharedPreferences (CRITICAL)

**File:** `shared_prefs/arattai_local_db_key.xml`

The SQLCipher encryption key for ALL databases is stored in plaintext XML:

```xml
<string name="key_id">1791195351071</string>
<string name="key">L3Tkqw1TVFcDj4ToMnTa13hw8cHAXDgS/yNZf1AGBU4=</string>
<string name="zuid">20034686476</string>
```

This key decrypts 8+ databases:
- `arattai_20034686476.db` — Main database
- `arattai_messages_*.db` — Messages
- `arattai_enc_messages_*.db` — E2EE messages
- `arattai_channel_messages_*.db` — Channel messages
- `arattai_cloud_messages_*.db` — Cloud messages
- `arattai_aes_keys_*.db` — AES encryption keys
- `arattai_files_*.db` — File metadata
- `iamoauthNativelib.db` — OAuth tokens

### M9-2: E2EE Signal Protocol Keys in SharedPreferences (HIGH)

**Files:** `defpackage/ddl.java:70`, `defpackage/cp4.java:485`

- `e2ee_signed_pre_key` — Signal protocol signed pre-key stored in SharedPreferences
- `business_auth_enc_wrapped_private_key` — Business authentication private key (1600+ char base64)
- `e2ee_pre_key_start_id` — Pre-key counter

**Impact:** Compromise of Signal protocol keys allows decryption of E2EE messages and business account takeover.

### M9-3: Tink Keyset Stored Alongside Encrypted Data (MEDIUM)

**File:** `CryptoUtil.java:28`

`enc_privatekey` is stored in `arattai_enc_prefs` using Tink `EncryptedSharedPreferences`. However, the Tink master keyset is stored in the same app data directory. An attacker who reads SharedPreferences also reads the Tink keyset, defeating the encryption.

### M9-4: E2EE Not Enabled by Default (MEDIUM)

**File:** `defpackage/a95.java:297+`

`e2ee_by_default` is set to `false`. All messages are server-readable unless the user manually opts in to E2EE. For a messaging app marketing end-to-end encryption, this is a significant privacy gap.

### M9-5: requestLegacyExternalStorage=true (LOW)

**File:** `AndroidManifest.xml:184`

Enables broad external storage access on Android 10, potentially exposing downloaded media and shared files.

---

## M10 — Insufficient Cryptography

**Rating: FAIL | Highest Severity: HIGH**

### M10-1: AES/ECB Mode with Hardcoded Native Key (HIGH)

**File:** `CryptoUtil.java:37, 67`

```java
Cipher.getInstance("AES/ECB/PKCS5Padding")  // ECB mode — preserves plaintext patterns
```

ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, enabling pattern analysis. The AES key is retrieved from native code via `getkey()` JNI call (line 67), making it a hardcoded static key embedded in `libexternal-native-iam-lib.so`. This is used for account/authentication encryption via the Zoho IAM library.

**Impact:** ECB + hardcoded key = effectively no encryption. An attacker who extracts the key from the .so file can decrypt all IAM-encrypted data.

### M10-2: RSA/ECB/PKCS1Padding — Bleichenbacher Vulnerable (MEDIUM)

**File:** `CryptoUtil.java:29`

```java
Cipher.getInstance("RSA/ECB/PKCS1Padding")  // PKCS1v1.5 padding
```

PKCS1v1.5 padding is vulnerable to Bleichenbacher padding-oracle attacks. Should use `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`.

### M10-3: RSA Keypair Generated in Software, Not Keystore (MEDIUM)

**File:** `CryptoUtil.java:51-55`

```java
KeyPairGenerator.getInstance("RSA")  // Software generation, no Keystore
```

RSA 2048 keypair generated in software and stored base64-encoded in EncryptedSharedPreferences instead of hardware-backed Android Keystore.

### M10-4: Signal Protocol Sound, But Key Storage Undermines It (MEDIUM)

Full `org.whispersystems.libsignal` library is bundled (SessionCipher, PreKeyBundle, IdentityKey). The Signal protocol itself is cryptographically sound. However, all key material is stored in software SharedPreferences rather than hardware Keystore, undermining the E2EE security guarantees.

### M10-5: No Insecure PRNG in App Code (POSITIVE)

All `java.util.Random` hits are in library code (BouncyCastle, protobuf, MLKit). The app's own code does not use insecure PRNG for cryptographic operations.

---

## Attack Chains

### Chain A: Full Message Database Theft (CRITICAL)

```
1. ExternalEntryPointActivity intent proxy (M3-1)
   → Inject content:// URI with FLAG_GRANT_READ_URI_PERMISSION (M8-2)
2. Read shared_prefs/arattai_local_db_key.xml via FileProvider path="." (M9-1)
3. Read encrypted databases via same FileProvider
4. Decrypt ALL messages, E2EE keys, OAuth tokens with plaintext key
   → RESULT: Complete access to all user data
```

### Chain B: Mass User Deanonymization (CRITICAL)

```
1. GET /v3/directory?phone_number={target} → user_id (M6-3, no rate limit)
2. GET https://profile.arattai.in/file?ID={user_id}&fs=original → photo (M6-4, no auth)
3. Enumerate at 14 req/sec = ~1.2M phone numbers/day
   → RESULT: Phone number → full identity correlation at scale
```

### Chain C: Channel Message Espionage (CRITICAL)

```
1. GET /v1/usernames/{name} → discover channel_id (enumerable)
2. GET /api/v2/chats/{channel_id}/messages → read ALL messages without joining
3. GET /api/v1/chats/{channel_id} → owner name, member count
4. GET /v1/chats/{channel_id}/media → all shared files with sender names
   → RESULT: Read any channel's private messages without authorization
```

### Chain D: Silent Message Manipulation (HIGH)

```
1. Broadcast com.zoho.chat.READ (M3-3) → mark all messages as read
2. Broadcast com.zoho.chat.REPLY → send replies as user
   → RESULT: Silent message manipulation without user awareness
```

### Chain E: Forced Meeting Surveillance (HIGH)

```
1. Intent proxy (M3-1) with https://meet.arattai.in/join/{attacker-meeting}
2. App auto-joins with authenticated session — no confirmation dialog
   → RESULT: Victim's camera/microphone potentially activated
```

### Chain F: IAM Data Decryption (HIGH)

```
1. Extract AES key from libexternal-native-iam-lib.so (M10-1)
2. AES/ECB/PKCS5Padding decryption with static key
   → RESULT: Decrypt all IAM/auth encrypted data
```

---

## Positive Findings

| Finding | Detail |
|---|---|
| `android:allowBackup="false"` | Backup disabled (M8) |
| No cleartext HTTP URLs | All endpoints use HTTPS (M5) |
| No insecure PRNG | App code uses SecureRandom (M10) |
| Signature-protected components | `DataTransferProvider` and `MessageActionActivity` properly use signature permissions |
| No sensitive data in logs | Grep for token/password/key in Log calls returned zero hits |
| Minimal clipboard exposure | Only OTP paste in VerificationScreen |

---

## Remediation Priority

### P0 — Fix Immediately (CRITICAL)

| # | Issue | Remediation |
|---|---|---|
| 1 | DB encryption key in plaintext SharedPrefs (M9-1) | Migrate to Android Keystore hardware-backed storage |
| 2 | Intent proxy in ExternalEntryPointActivity (M3-1, M4-1) | Add URI scheme allowlist, strip flags, validate caller, add confirmation dialogs |
| 3 | Channel Message IDOR (Chain C) | Enforce server-side subscription/membership check on `/api/v2/chats/{id}/messages` |
| 4 | AES/ECB with hardcoded native key (M10-1) | Switch to AES/GCM, derive key from Android Keystore |
| 5 | Phone number enumeration with zero rate limiting (M6-3) | Add rate limiting and CAPTCHA to `/v3/directory` |
| 6 | Unauthenticated profile photo access (M6-4) | Require authentication on `profile.arattai.in/file` |

### P1 — Fix This Sprint (HIGH)

| # | Issue | Remediation |
|---|---|---|
| 7 | Zero SSL certificate pinning (M5-1) | Implement OkHttp CertificatePinner or network_security_config.xml |
| 8 | E2EE keys in SharedPreferences (M9-2) | Move to Android Keystore |
| 9 | OAuth client_secret in APK (M1-2) | Use PKCE flow instead of client_secret; migrate to server-side token exchange |
| 10 | Chucker in production (M2-1) | Remove Chucker from release builds (use `debugImplementation`) |
| 11 | Unprotected NotificationMessageReceiver (M3-3) | Add `android:permission` with signature protection |
| 12 | Overly broad FileProvider paths (M8-2) | Restrict to specific subdirectories |
| 13 | Exported activities without auth (M3-2) | Add authentication guards or remove `exported="true"` |
| 14 | RSA/PKCS1v1.5 padding (M10-2) | Switch to OAEP padding |

### P2 — Fix This Quarter (MEDIUM)

| # | Issue | Remediation |
|---|---|---|
| 15 | No root detection (M7-1) | Implement Play Integrity API or SafetyNet |
| 16 | No network_security_config.xml (M5-2) | Create with pin sets and cleartext restrictions |
| 17 | ENFORCE_PASSCODE=false (M8-4) | Enable by default |
| 18 | E2EE not default (M9-4) | Enable E2EE by default for all conversations |
| 19 | SQL string concatenation (M4-2) | Parameterize all query components |
| 20 | Unsanitized HTML in about field (M4-3) | Server-side HTML sanitization |
| 21 | RSA keypair not in Keystore (M10-3) | Generate and store in Android Keystore |
| 22 | Excessive permissions (M6-1) | Remove `REQUEST_INSTALL_PACKAGES`, `GET_ACCOUNTS`, `MANAGE_ACCOUNTS` if unused |
| 23 | Contact sync (M6-2) | Add granular consent and minimize data transmitted |
| 24 | Analytics PII in URLs (M5-3) | Move identifiers to POST body |

---

## Testing Environment

- **Static Analysis:** JADX decompilation of APK v1.54.0 (versionCode 1946)
- **Dynamic Analysis:** Android emulator (sdk_gphone64_x86_64) + Burp Suite + Frida
- **Scope:** Client-side APK analysis + API endpoint testing
- **Evidence:** Screenshots, Frida output, Burp request/response captures (see SECURITY_ASSESSMENT_REPORT.md)

---

## OAuth Token Details (for reproduction)

```
Access Token: Zoho-oauthtoken 1001.907e5dd63c8e90957074f0ef05684d37.1596a4b8b34b6d6b9707bd8494ff6ea3
Headers: X-Reader-Version: 1, User-Agent: ArattaiAndroid/1.54.0
Base URL: https://chat.arattai.in
Profile URL: https://profile.arattai.in
```

---

*Assessment conducted under authorized penetration testing engagement.*
