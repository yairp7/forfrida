#!/usr/bin/python

import sys
import frida
import time
from getopt import getopt

num_args = len(sys.argv)

if num_args < 2:
   print 'Not enought arguments!'
   sys.exit(2)

codes_added = []

# JavaScript to be injected
js_file = open('hook.js', 'rw+')
frida_code = js_file.read()

colors = { "time" : "\x1b[33m", "source" : "\x1b[37m", "args" : "\x1b[35m", "result" : "\x1b[32m" }

def getTime():
   return time.strftime("%H:%M:%S")

def baselog(msg):
   logmessage = colors['time'] + '[' + getTime() + '] ' + colors['source'] + msg
   print logmessage

def log(source, args, result):
   baselog(colors['source'] + source + '(' + colors['args'] + args + colors['source'] + ') => ' + colors['result'] + result)

def replace_code(frida_code, new_code, placeholder):
   to_replace = placeholder
   to_replace_length = len(to_replace)
   index = frida_code.find(to_replace)
   frida_code_length = len(frida_code)
   return frida_code[0:index] + js + frida_code[index + to_replace_length:frida_code_length]

def add_code(frida_code, code_filename):
   if code_filename not in codes_added:
      code_file = open('code/' + code_filename, 'r')
      code = code_file.read()
      frida_code = code + '\n' + frida_code
      codes_added.append(code_filename)
   return frida_code

# See if theres relevant arguments
if num_args > 2:
   classes = ''
   try:
      opts, args = getopt(sys.argv[2:], "hac:m:", ["all-classes", "classes=", "methods="])
   except getopt.GetoptError:
      print 'helper.py <android-app-package-name> -c <class1,class2,...> -m <class1:method1,class2:method2,...>'
      sys.exit(2)

   for opt, arg in opts:
      js = ''
      if opt == '-h':
         print 'helper.py <android-app-package-name> OPTIONS'
         print 'Options:'
         print '-a => Print all classes'
         print '-c <class1,class2,...> => Hook all methods in the provided classes'
         print '-m <class1:method1,class2:method2,...> => Hook these specific methods'
         sys.exit()
      elif opt in ("-a", "--all-classes"):
         frida_code = add_code(frida_code, 'print_classes.js')
         placeholder = '//OTHERS_TO_ADD'
         js = "printAllClasses();"
         js += placeholder
         frida_code = replace_code(frida_code, js, placeholder)
      elif opt in ("-c", "--classes"):
         if not arg:
            print 'Not enought arguments!'
            sys.exit(2)
         frida_code = add_code(frida_code, 'hook_class.js')
         placeholder = '//CLASSES_TO_ADD'
         classes = arg
         classes = classes.split(',')
         for c in classes:
            js += "hookall('" + c + "', 'a');"
         js += placeholder
         frida_code = replace_code(frida_code, js, placeholder)
      elif opt in ("-m", "--methods"):
         if not arg:
            print 'Not enought arguments!'
            sys.exit(2)
         frida_code = add_code(frida_code, 'hook_method.js')
         placeholder = '//METHODS_TO_ADD'
         methods = arg
         methods = methods.split(',')
         for m in methods:
            mp = m.split(':')
            _c = mp[0]
            _m = mp[1]
            js += "hook('" + _c + "', '" + _m + "', false);";
         js += placeholder
         frida_code = replace_code(frida_code, js, placeholder)

   print 'Generated Script:\n ' + frida_code

js_file.close()

def message_callback(message, data):
   if 'payload' in message:
      if 'msg' in message['payload']:
         msg = message['payload']['msg']
         baselog(msg)
      else:
         source = 'No Source'
         args = 'No Args'
         result = 'No Result'
         if 'source' in message['payload']:
            source = message['payload']['source']
         if 'args' in message['payload']:
            args = message['payload']['args']
         if 'result' in message['payload']:
            result = message['payload']['result']
         log(source, args, result)

app = sys.argv[1] # <package>

device = frida.get_usb_device()

pid = device.spawn([app])
device.resume(pid)
time.sleep(1) # Without it Java.perform silently fails

process = device.attach(pid)

script = process.create_script(frida_code)
script.on('message', message_callback)
script.load()

sys.stdin.read()