import frida
import sys
import time

device = frida.get_usb_device()
session = device.attach(3915)

with open(r"D:\aratai\poc\webview_live_hook.js", "r") as f:
    script_code = f.read()

script = session.create_script(script_code)

def on_message(message, data):
    if message["type"] == "send":
        print(str(message["payload"]), flush=True)
    elif message["type"] == "log":
        print(message["payload"], flush=True)
    else:
        print(str(message), flush=True)

script.on("message", on_message)
script.load()
print("[*] Hooks loaded. Waiting 10s for existing WebViews...", flush=True)
time.sleep(10)
session.detach()
print("[*] Done.", flush=True)
