import sys
import frida

# JavaScript to be injected
js_file = open('hook.js', 'r')
frida_code = js_file.read()
js_file.close()

def message_callback(message, data):
    print(message)

app = "<app-name>"

process = frida.get_usb_device().attach(app)
script = process.create_script(frida_code)
script.on('message', message_callback)
script.load()

sys.stdin.read()