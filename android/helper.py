#!/usr/bin/python

import sys
import frida
import time
from getopt import getopt

num_args = len(sys.argv)

if num_args < 2:
   print 'Not enought arguments!'
   sys.exit(2)

# JavaScript to be injected
js_file = open('hook.js', 'rw+')
frida_code = js_file.read()

def replace_code(frida_code, new_code, placeholder):
   to_replace = placeholder
   to_replace_length = len(to_replace)
   index = frida_code.find(to_replace)
   frida_code_length = len(frida_code)
   return frida_code[0:index] + js + frida_code[index + to_replace_length:frida_code_length]

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
         placeholder = '//OTHERS_TO_ADD'
         js = "printAllClasses();"
         js += placeholder
         frida_code = replace_code(frida_code, js, placeholder)
      elif opt in ("-c", "--classes"):
         if not arg:
            print 'Not enought arguments!'
            sys.exit(2)
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
         placeholder = '//METHODS_TO_ADD'
         methods = arg
         methods = methods.split(',')
         for m in methods:
            mp = m.split(':')
            _c = mp[0]
            _m = mp[1]
            js += "hook('" + _c + "', '" + _m + "');";
         js += placeholder
         frida_code = replace_code(frida_code, js, placeholder)

   print 'Frida Script:\n ' + frida_code

js_file.close()

def message_callback(message, data):
    print(message)

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