#!/usr/bin/python

import sys
import os
import time
from getopt import getopt
from setup import setup, android_setup_frida_server, android_close_frida_server, android_is_frida_running
from utils import baselog, log, add_code, replace_code, android_get_devices, android_get_processes

CODE_DIR = os.path.dirname(os.path.abspath(__file__))

# Check user input 
num_args = len(sys.argv)

if num_args < 2:
   print 'Not enought arguments!'
   sys.exit(2)

codes_added = []

# JavaScript to be injected
js_file = open(CODE_DIR + '/hook.js', 'rw+')
frida_code = js_file.read()
output_file = None
is_quiet = False

def finish(exit_code):
   if output_file:
      output_file.close()
   devices = android_get_devices()
   for device in devices:
      baselog('[{0}] Closing frida-server...'.format(device))
      android_close_frida_server(device)
   sys.stdin.close()
   sys.exit(exit_code)

def call_add_code(frida_code, code_filename):
   if code_filename not in codes_added:
      frida_code = add_code(frida_code, code_filename)
      codes_added.append(code_filename)
   return frida_code

# See if theres relevant arguments
if num_args > 2:
   classes = ''
   try:
      opts, args = getopt(sys.argv[2:], "hqo:ac:m:", ["quiet", "output=", "all-classes", "classes=", "methods="])
   except getopt.GetoptError:
      print 'helper.py <android-app-package-name> -c <class1,class2,...> -m <class1:method1,class2:method2,...>'
      sys.exit(2)

   for opt, arg in opts:
      js = ''
      if opt == '-h':
         print 'helper.py <android-app-package-name> OPTIONS'
         print 'Options:'
         print '-o => Output file'
         print '-a => Print all classes'
         print '-c <class1,class2,...> => Hook all methods in the provided classes'
         print '-m <class1:method1,class2:method2,...> => Hook these specific methods'
         sys.exit()
      elif opt in ("-q", "--quiet"):
         is_quiet = True
      elif opt in ("-o", "--output"):
         if not arg:
            print 'Not enought arguments!'
            sys.exit(2)
         output_file = open(arg, 'w+')
      elif opt in ("-a", "--all-classes"):
         code_filename = 'print_classes.js'
         frida_code = call_add_code(frida_code, code_filename)
         placeholder = '//OTHERS_TO_ADD'
         js = "printAllClasses();"
         js += placeholder
         frida_code = replace_code(frida_code, js, placeholder)
      elif opt in ("-c", "--classes"):
         if not arg:
            print 'Not enought arguments!'
            sys.exit(2)
         code_filename = 'hook_class.js'
         frida_code = call_add_code(frida_code, code_filename)
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
         code_filename = 'hook_method.js'
         frida_code = call_add_code(frida_code, code_filename)
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

   # baselog('Generated Script:\n ' + frida_code)

js_file.close()

def message_callback(message, data):
   if output_file:
      write_to_file = True
   else:
      write_to_file = False
   msg_to_write = None
   if 'payload' in message:
      if 'msg' in message['payload']:
         msg = message['payload']['msg']
         msg_to_write = baselog(msg, write_to_file, is_quiet)
      elif 'command' in message['payload']:
         cmd = message['payload']['command']
         params = message['payload']['params']
         if 'finish' in cmd:
            if params and len(params) > 0:
               exit_code = params[0]
               finish(exit_code)
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
         msg_to_write = log(source, args, result, write_to_file, is_quiet)
   if output_file:
      if msg_to_write:
         output_file.write(msg_to_write + '\n')

app = sys.argv[1] # <package>

# Make sure everything is installed
baselog('Making sure everything is installed...')
if setup():
   import frida

   try:
      baselog('Getting connected devices...')
      devices = frida.get_device_manager().enumerate_devices()
      if devices and len(devices) > 0:
         for device in devices:
            if device.type == 'usb':
               is_device_prepared = android_setup_frida_server(device.id)
               if not is_device_prepared:
                  baselog('No devices to work with!')
                  finish(2)
               pid = None
               try:
                  should_spawn = True
                  for proc in device.enumerate_processes():
                     if app in proc.name:
                        pid = int(proc.pid)
                        should_spawn = False;
                  if should_spawn:
                     baselog('[{0}] Starting app {1}...'.format(device.id, app))
                     pid = device.spawn([app])
                     baselog('[{0}] App {1}:{2} started...'.format(device.id, app, str(pid)))
                     device.resume(pid)
                     baselog('[{0}] App {1}:{2} resumed...'.format(device.id, app, str(pid)))
                  time.sleep(1) # Without it Java.perform silently fails
                  process = device.attach(pid)
                  if process:
                     baselog('[{0}] Attached to app {1}:{2}...'.format(device.id, app, str(pid)))
                     script = process.create_script(frida_code)
                     script.on('message', message_callback)
                     script.load()
               except Exception as e:
                  print e
                  if 'unable to find/load application' in str(e):
                     baselog('Package {0} is not installed on device!'.format(app))
                     finish(2)
      else:
         baselog('No devices found!')
   except frida.TimedOutError as e:
      baselog("No devices connected, or there's a problem with the devices.")
      finish(2)
   sys.stdin.read()
else:
   baselog('Failed to setup!')
   finish(2)