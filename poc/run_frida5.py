import frida
import time

device = frida.get_usb_device()
pid = device.spawn(['com.aratai.chat'])
session = device.attach(pid)

js = '''
setTimeout(function() {
    if (typeof Java === 'undefined') {
        console.log('[ERROR] Java runtime not available');
        console.log('[INFO] Process runtime: ' + Process.runtime);
    } else {
        console.log('[OK] Java runtime available');
        Java.perform(function() {
            console.log('[*] Inside Java.perform');
            var WebView = Java.use('android.webkit.WebView');
            console.log('[*] WebView class loaded');
            
            WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
                console.log('[LOAD] ' + url);
                var s = this.getSettings();
                console.log('[SETTINGS] JS=' + s.getJavaScriptEnabled() + ' FileAccess=' + s.getAllowFileAccess() + ' ContentAccess=' + s.getAllowContentAccess() + ' MixedContent=' + s.getMixedContentMode());
                if (s.getAllowFileAccess() && s.getJavaScriptEnabled()) {
                    console.log('[!!!] VULNERABLE: JS+FileAccess enabled!');
                }
                return this.loadUrl(url);
            };

            WebView.addJavascriptInterface.implementation = function(obj, name) {
                console.log('[BRIDGE] name="' + name + '" class=' + obj.getClass().getName());
                return this.addJavascriptInterface(obj, name);
            };

            var WebSettings = Java.use('android.webkit.WebSettings');
            WebSettings.setAllowFileAccess.implementation = function(v) { console.log('[SET] AllowFileAccess=' + v); return this.setAllowFileAccess(v); };
            WebSettings.setJavaScriptEnabled.implementation = function(v) { console.log('[SET] JSEnabled=' + v); return this.setJavaScriptEnabled(v); };
            WebSettings.setMixedContentMode.implementation = function(v) { console.log('[SET] MixedContent=' + v); return this.setMixedContentMode(v); };

            console.log('[*] All hooks installed!');

            Java.choose('android.webkit.WebView', {
                onMatch: function(wv) { console.log('[FOUND] Existing WebView URL=' + wv.getUrl()); },
                onComplete: function() { console.log('[*] Scan complete.'); }
            });
        });
    }
}, 3000);

console.log('[*] Script loaded. Runtime: ' + (typeof Java !== 'undefined' ? 'Java available' : 'Java NOT available yet'));
console.log('[*] Process.runtime = ' + (typeof Process !== 'undefined' ? 'defined' : 'undefined'));
'''

script = session.create_script(js, runtime='v8')

def on_message(message, data):
    if message['type'] == 'log':
        print(message['payload'], flush=True)
    else:
        print(str(message), flush=True)

script.on('message', on_message)
script.load()
device.resume(pid)
print('[HOST] Waiting 30s...', flush=True)
time.sleep(30)
session.detach()
print('[HOST] Done.', flush=True)