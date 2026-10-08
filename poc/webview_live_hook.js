Java.perform(function() {
    console.log('[*] Hooking WebView...');
    
    // Hook WebView.loadUrl
    var WebView = Java.use('android.webkit.WebView');
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        console.log('[LOAD] ' + url);
        var s = this.getSettings();
        console.log('[SETTINGS] JS=' + s.getJavaScriptEnabled() + 
            ' FileAccess=' + s.getAllowFileAccess() + 
            ' ContentAccess=' + s.getAllowContentAccess() + 
            ' MixedContent=' + s.getMixedContentMode() +
            ' DomStorage=' + s.getDomStorageEnabled());
        if (s.getAllowFileAccess() && s.getJavaScriptEnabled()) {
            console.log('[!!!] VULNERABLE: JS+FileAccess enabled!');
        }
        return this.loadUrl(url);
    };

    // Hook addJavascriptInterface
    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log('[BRIDGE] addJavascriptInterface("' + name + '") class=' + obj.getClass().getName());
        var methods = obj.getClass().getMethods();
        for (var i = 0; i < methods.length; i++) {
            var anns = methods[i].getAnnotations();
            for (var j = 0; j < anns.length; j++) {
                if (anns[j].toString().indexOf('JavascriptInterface') !== -1) {
                    console.log('[BRIDGE-METHOD] @JavascriptInterface ' + methods[i].getName() + '(' + methods[i].getParameterTypes().length + ' args)');
                }
            }
        }
        return this.addJavascriptInterface(obj, name);
    };

    // Hook WebSettings
    var WebSettings = Java.use('android.webkit.WebSettings');
    WebSettings.setAllowFileAccess.implementation = function(v) {
        console.log('[SET] setAllowFileAccess(' + v + ')');
        return this.setAllowFileAccess(v);
    };
    WebSettings.setJavaScriptEnabled.implementation = function(v) {
        console.log('[SET] setJavaScriptEnabled(' + v + ')');
        return this.setJavaScriptEnabled(v);
    };
    WebSettings.setMixedContentMode.implementation = function(v) {
        var m = v === 0 ? 'ALWAYS_ALLOW' : v === 1 ? 'NEVER_ALLOW' : 'COMPAT';
        console.log('[SET] setMixedContentMode(' + m + ')');
        return this.setMixedContentMode(v);
    };
    WebSettings.setAllowContentAccess.implementation = function(v) {
        console.log('[SET] setAllowContentAccess(' + v + ')');
        return this.setAllowContentAccess(v);
    };

    // Scan for existing WebViews
    console.log('[*] Scanning for existing WebViews...');
    Java.choose('android.webkit.WebView', {
        onMatch: function(wv) {
            var s = wv.getSettings();
            console.log('[EXISTING] URL=' + wv.getUrl() + 
                ' JS=' + s.getJavaScriptEnabled() + 
                ' FileAccess=' + s.getAllowFileAccess());
        },
        onComplete: function() { console.log('[*] Scan done. Hooks active — trigger a MiniApp now.'); }
    });
});
