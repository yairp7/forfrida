import subprocess
from utils import _exec_command, _exec_command_timed, android_get_devices, baselog, CODE_DIR

FRIDA_SERVER_VERSION = '12.2.18'
FRIDA_SERVER_PATH = '/data/local/tmp/frida-server';

def setup():
	# Check if frida-tools exists, and if not install
	try:
		import frida
		return True
	except ImportError:
		baselog('Frida is not installed, so installing...')
		if(install_frida_tools() == 0):
			baselog('Frida installed successfully!')
			return True
		else:
			baselog('Failed to install frida, exiting!')
			exit(2)
	return False

def install_frida_tools():
	cmd = ['pip', 'install', 'frida-tools']
	p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
	p.wait()
	return p.returncode == 0

def android_is_device_rooted(device):
	cmd = ['adb', '-s', device, 'shell', 'ls', '/data/data']
	output = _exec_command(cmd)
	if output and 'Permission denied' in output:
		return False
	return True

def android_get_frida_server_by_cpu(device):
	cmd = ['adb', '-s', device, 'shell', 'cat', '/proc/cpuinfo']
	output = _exec_command(cmd)
	frida_server = None
	if 'ARMv7' in output:
		baselog('[{0}] frida-server for 32bit selected'.format(device))
		frida_server = CODE_DIR + '/frida-server/' + 'frida-server-' + FRIDA_SERVER_VERSION + '-android-arm'
	elif 'ARMv8' in output or 'AArch64' in output:
		baselog('[{0}] frida-server for 64bit selected'.format(device))
		frida_server = CODE_DIR + '/frida-server/' + 'frida-server-' + FRIDA_SERVER_VERSION + '-android-arm64'
	return frida_server

def android_close_frida_server(device):
	cmd = ['adb', '-s', device, 'shell', 'killall', '-s', '9', 'frida-server']
	output = _exec_command(cmd)
	print output
	baselog('[{0}] frida-server killed!'.format(device))

def android_is_frida_running(device):
	cmd = ['adb', '-s', device, 'shell', 'ps', '|', 'grep', 'frida-server']
	out, err = _exec_command_timed(cmd, timeout=10)
	if out and '/frida-server' in out:
		return True
	return False

def android_is_frida_installed(device):
	cmd = ['adb', '-s', device, 'shell', 'ls', FRIDA_SERVER_PATH]
	out, err = _exec_command_timed(cmd, timeout=10)
	if out and '/frida-server' in out:
		return True
	return False

def android_install_frida(device):
	baselog('[{0}] Finding the relevant frida-server...'.format(device))
	frida_server = android_get_frida_server_by_cpu(device)
	baselog('[{0}] Pushing frida-server...'.format(device))
	cmd = ['adb', '-s', device, 'push', frida_server, '/data/local/tmp/frida-server']
	output = _exec_command(cmd)
	if output and '1 file pushed' in output:
		frida_server_file = '/data/local/tmp/frida-server'
		baselog('[{0}] Setting chmod +x for frida-server...'.format(device))
		cmd = ['adb', '-s', device, 'shell', 'chmod', '+x', FRIDA_SERVER_PATH]
		_exec_command(cmd)
		return True
	return False

def android_run_frida(device):
	baselog('[{0}] Starting frida-server...'.format(device))
	cmd = ['adb', '-s', device, 'shell', '.' + FRIDA_SERVER_PATH, '&']
	_exec_command_timed(cmd, timeout=10)
	return android_is_frida_running(device)

def android_setup_frida_server(device):
	frida_installed = False
	frida_running = False
	if not android_is_device_rooted(device):
		baselog("[{0}] Can't install frida-server, device not rooted!".format(device))
	else:
		baselog('[{0}] Device is rooted...'.format(device))
		if android_is_frida_running(device):
			baselog('[{0}] frida-server is running!'.format(device))
			frida_installed = True
			frida_running = True
		elif android_is_frida_installed(device):
			baselog('[{0}] frida-server is installed!'.format(device))
			frida_installed = True
			
		if not frida_installed:
			frida_installed = android_install_frida(device)
			if frida_installed:
				baselog('[{0}] frida-server is installed!'.format(device))
		if frida_installed and not frida_running:
			frida_running = android_run_frida(device)
			if frida_running:
				baselog('[{0}] frida-server is running!'.format(device))	
	return frida_installed and frida_running
