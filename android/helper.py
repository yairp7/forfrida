import sys
import frida
import time

# JavaScript to be injected
js_file = open('hook.js', 'r')
frida_code = js_file.read()
js_file.close()

def message_callback(message, data):
    print(message)

app = "<package>"

device = frida.get_usb_device()

pid = device.spawn([app])
device.resume(pid)
time.sleep(1) # Without it Java.perform silently fails

process = device.attach(pid)

script = process.create_script(frida_code)
script.on('message', message_callback)
script.load()

sys.stdin.read()