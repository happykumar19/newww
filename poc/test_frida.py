import frida, time
device = frida.get_usb_device()
print('Processes:', flush=True)
for p in device.enumerate_processes():
    if 'aratai' in p.name.lower():
        print(f'  PID={p.pid} Name={p.name}', flush=True)

print('Attaching...', flush=True)
session = device.attach('com.aratai.chat')
print('Attached!', flush=True)

script = session.create_script('console.log("Hello from: " + (typeof Java !== "undefined" ? "Java available" : "NO JAVA"));')
def on_msg(msg, data):
    print(str(msg), flush=True)
script.on('message', on_msg)
script.load()
time.sleep(3)
session.detach()
print('Done', flush=True)