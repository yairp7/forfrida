import time
import os
from subprocess import Popen, check_output, PIPE

CODE_DIR = os.path.dirname(os.path.abspath(__file__))

def get_color(type):
	colors = { "time" : "\x1b[33m", "source" : "\x1b[37m", "args" : "\x1b[35m", "result" : "\x1b[32m" }
	return colors[type]

def getTime():
   return time.strftime("%H:%M:%S")

def baselog(msg, only_data=False, is_quiet=False):
	message = '{0}{1}{2}{3}'
	logmessage = message.format(get_color('time'), '[' + getTime() + ']', get_color('source'), ' ' + msg)
	if not is_quiet:
		print logmessage
	if only_data:
		return message.format('', '', '', msg)
	else:
		return logmessage

def log(source, args, result, only_data=False, is_quiet=False):
   return baselog(get_color('source') + source + '(' + get_color('args') + args + get_color('source') + ') => ' + get_color('result') + result, only_data, is_quiet)

def replace_code(frida_code, new_code, placeholder):
	to_replace = placeholder
	to_replace_length = len(to_replace)
	index = frida_code.find(to_replace)
	frida_code_length = len(frida_code)
	return frida_code[0:index] + new_code + frida_code[index + to_replace_length:frida_code_length]

def add_code(frida_code, code_filename):
	code_file = open(CODE_DIR + '/code/' + code_filename, 'r')
	code = code_file.read()
	frida_code = code + '\n' + frida_code
	code_file.close()
	return frida_code

# From SILQ

class CalledProcessError(Exception):
    """This exception is raised when a process run by check_call() or
    check_output() returns a non-zero exit status.
    The exit status will be stored in the returncode attribute;
    check_output() will also store the output in the output attribute.
    """
    def __init__(self, returncode, cmd, output=None):
        self.returncode = returncode
        self.cmd = cmd
        self.output = output
    def __str__(self):
        return "Command '%s' returned non-zero exit status %d" % (self.cmd, self.returncode)

class TimeoutExpired(Exception):
    """This exception is raised when the timeout expires while waiting for a
    child process.
    """
    def __init__(self, cmd, timeout, output=None):
        self.cmd = cmd
        self.timeout = timeout
        self.output = output

    def __str__(self):
        return ("Command '%s' timed out after %s seconds" %
                (self.cmd, self.timeout))

def _exec_command_timed(cmd, timeout=10, pipe_stdout=False):
	stdout = None
	stderr = None
	from threading import Timer
	kill = lambda process: process.kill()
	pipe = PIPE
	if pipe_stdout:
		pipe = -1
	p = Popen(cmd, stdout=pipe, stderr=pipe)
	timout_timer = Timer(timeout, kill, [p])
	try:
	    timout_timer.start()
	    stdout, stderr = p.communicate()
	finally:
	    timout_timer.cancel()
	return stdout, stderr

def _exec_command(cmd):
	returned_output = ''
	try:
		returned_output = check_output(cmd)
	except Exception as e:
		if 'output' in e:
			returned_output = e.output
		else:
			returned_output = str(e)
	
	if returned_output:
		returned_output = returned_output.decode("utf-8")
	return returned_output

def _parse_device_list(devices):
    res = []
    for x in devices.split('\n')[1:]:
        device = x.split()
        if len(device) == 2 and device[1] == 'device':
            res.append(device[0])
    return res

def android_get_devices():
	cmd = ['adb', 'devices']
	output = _exec_command(cmd)
	lines = output.count("\n")
	if lines <= 2:  # Error
		return None
	return _parse_device_list(output)

def android_get_processes(device):
	cmd = ['adb', '-s', device, 'shell', 'ps']
	print str(cmd)
	stdout, stderr = _exec_command_timed(cmd, timeout=10)
	print stderr
	return None