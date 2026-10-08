import frida
import time

device = frida.get_usb_device()

# Spawn the app so Java runtime is guaranteed ready
pid = device.spawn(["com.aratai.chat"])
session = device.attach(pid)

js = '''
Java.perform(function() {
    console.log('[*] Hooking WebView...');
    var WebView = Java.use('android.webkit.WebView');
    
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        console.log('[LOAD] ' + url);
        var s = this.getSettings();
        console.log('[SETTINGS] JS=' + s.getJavaScriptEnabled() + ' FileAccess=' + s.getAllowFileAccess() + ' ContentAccess=' + s.getAllowContentAccess() + ' MixedContent=' + s.getMixedContentMode() + ' DomStorage=' + s.getDomStorageEnabled());
        if (s.getAllowFileAccess() && s.getJavaScriptEnabled()) {
            console.log('[!!!] VULNERABLE: JS+FileAccess enabled!');
        }
        return this.loadUrl(url);
    };

    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log('[BRIDGE] addJavascriptInterface name="' + name + '" class=' + obj.getClass().getName());
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

    console.log('[*] All hooks installed. Monitoring for WebView creation...');
});
'''

script = session.create_script(js)

def on_message(message, data):
    if message['type'] == 'log':
        print(message['payload'], flush=True)
    elif message['type'] == 'send':
        print(str(message['payload']), flush=True)
    else:
        print(str(message), flush=True)

script.on('message', on_message)
script.load()
device.resume(pid)
print('[HOST] App spawned with hooks. Waiting 20s for app to load...', flush=True)
time.sleep(20)
session.detach()
print('[HOST] Done.', flush=True)