/*
 * Arattai (com.aratai.chat) - SSL Pinning Bypass
 *
 * Usage:
 *   frida -U -f com.aratai.chat -l frida_ssl_bypass.js --no-pause
 *
 * Or with objection:
 *   objection -g com.aratai.chat explore
 *   android sslpinning disable
 *
 * Note: Previous assessment confirmed ZERO SSL pinning in Arattai v1.54.0.
 * This script is included for completeness and future versions that may add pinning.
 */

Java.perform(function() {
    console.log('[*] Arattai SSL Pinning Bypass loaded');
    console.log('[*] Target: com.aratai.chat');

    // ========== 1. OkHttp3 CertificatePinner ==========
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');

        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] OkHttp3 CertificatePinner.check() bypassed for: ' + hostname);
            return;
        };

        try {
            CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, certs) {
                console.log('[+] OkHttp3 CertificatePinner.check(String, Certificate[]) bypassed for: ' + hostname);
                return;
            };
        } catch(e) {}

        console.log('[+] OkHttp3 CertificatePinner hooked');
    } catch(e) {
        console.log('[-] OkHttp3 CertificatePinner not found: ' + e.message);
    }

    // ========== 2. TrustManagerImpl (Android system) ==========
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');

        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] TrustManagerImpl.verifyChain() bypassed for: ' + host);
            return untrustedChain;
        };
        console.log('[+] TrustManagerImpl hooked');
    } catch(e) {
        console.log('[-] TrustManagerImpl not found: ' + e.message);
    }

    // ========== 3. Custom X509TrustManager ==========
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        var TrustManager = Java.registerClass({
            name: 'com.arattai.poc.TrustAllCerts',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() {
                    return [];
                }
            }
        });

        var TrustManagers = [TrustManager.$new()];
        var sslContext = SSLContext.getInstance('TLS');
        sslContext.init(null, TrustManagers, null);

        console.log('[+] Custom TrustAll X509TrustManager registered');
    } catch(e) {
        console.log('[-] Custom TrustManager failed: ' + e.message);
    }

    // ========== 4. WebViewClient SSL error handler ==========
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log('[+] WebViewClient.onReceivedSslError() -> proceeding');
            handler.proceed();
        };
        console.log('[+] WebViewClient SSL error handler hooked');
    } catch(e) {
        console.log('[-] WebViewClient hook failed: ' + e.message);
    }

    // ========== 5. Arattai-specific: Zoho SSO SSL ==========
    try {
        var zohoCerts = Java.use('com.zoho.accounts.zohoaccounts.nativelibrary.b');
        if (zohoCerts) {
            console.log('[+] Zoho accounts SSL class found - monitoring');
        }
    } catch(e) {
        console.log('[-] Zoho accounts SSL class not found');
    }

    // ========== 6. Network Security Config bypass ==========
    try {
        var NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
        NetworkSecurityConfig.isCleartextTrafficPermitted.overload().implementation = function() {
            console.log('[+] NetworkSecurityConfig: cleartext permitted');
            return true;
        };
        console.log('[+] NetworkSecurityConfig hooked');
    } catch(e) {
        console.log('[-] NetworkSecurityConfig not found: ' + e.message);
    }

    console.log('[*] All SSL bypass hooks installed');
    console.log('[*] Configure Burp proxy on device Wi-Fi settings');
    console.log('[*] Burp CA must be installed as system cert on the device');
});
