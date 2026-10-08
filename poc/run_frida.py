import frida
import sys
import time

device = frida.get_usb_device()
session = device.attach("com.aratai.chat")

with open(r"D:\aratai\poc\webview_live_hook.js", "r") as f:
    script_code = f.read()

script = session.create_script(script_code)

output_lines = []
def on_message(message, data):
    if message["type"] == "send":
        line = str(message["payload"])
    else:
        line = str(message)
    output_lines.append(line)
    print(line, flush=True)

script.on("message", on_message)
script.load()
print("[*] Frida hooks loaded. Waiting 10 seconds...", flush=True)
time.sleep(10)
session.detach()
print("[*] Done. Total output lines:", len(output_lines), flush=True)
