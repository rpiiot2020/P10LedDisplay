import socket
import os
import sys
import random
import time # This code uses time.time() which might have an upper limit issue in the future. Please
# see https://docs.python.org/3/library/time.html : "The functions in this module may not handle
# dates and times before the epoch or far in the future. The cut-off point in the future is determined
#  by the C library; for 32-bit systems, it is typically in 2038."
from datetime import date, timedelta
import threading
from array import array
# Additional steps needed
# pyOpenSSL needs to be installed using pip
# - note if using Python3, substitute 'pip3' in line above.
# http://flask.pocoo.org/snippets/111/
from OpenSSL import SSL
import configparser
import logging
import logging.handlers
import subprocess
import base64

# Refer to https://docs.python.org/3/howto/logging.html
#
# Perform logger configuration in 'main' instead of here since *_Req.py also imports
#  this file . Else the handlers would be wrongly added twice to log twice. Experiment by
#  placing a breakpoint in the following print statement & check the call stack:
#
#print("main module executing.")  # Uncomment & palce brerakpoint to check if executes twice.
#
# Continue logger configuration at 'main'.
logger = logging.getLogger() # Get the 'root' logger & configure it. Run multiple times is ok,
#  since there is only one instance.

import ERROR_Code

from flask import Flask, jsonify
from flask import abort
from flask import make_response
from flask import request
from paho.mqtt import client as mqtt_client

app = Flask(__name__)

# From https://pythonhosted.org/PyInstaller/runtime-information.html
#
# Please use "actual__file__dir" , instead of "os.path.dirname(__file__)",
# to allow obfuscated Python code to run without changing current directory
# to where *.py resides. This is needed to run the obfuscated Python code
# to run as a daemon.
#
if getattr(sys, 'frozen', False):
    # we are running in a bundle
    actual__file__dir = sys._MEIPASS
else:
    # we are running in a normal Python environment
    actual__file__dir = os.path.dirname(os.path.abspath(__file__))

# Initialize values from configparser
config = configparser.ConfigParser()
config.read(os.path.join(actual__file__dir, 'conf/config.ini'))

# General Parameters
#===================
g_PNSAppServices_IPWhiteList = config['LocalAgent']['PNS_AppServices_IP_WhiteList'] # IP White List for PNS App Services.
command_execute = config['LocalAgent']['Command']
arg = config['LocalAgent']['Arg']





# Detect OS in order to detect LAN IP of localhost automatically
if os.name != "nt":
    import fcntl
    import struct


    def get_interface_ip(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s',
                                                                            bytes(ifname[:15], 'utf8')))[20:24])


def get_lan_ip():
    return "0.0.0.0" #  On PyCharm, Workaround for: socket.gaierror: [Errno 8] nodename nor servname provided, or not known
    #  Also comment the remainder of the function. Use 127.0.0.1 to connect via Postman locally, if 192.168.?.?, etc is not working.
    #  Remember to UNDO this code for the workaround before sending over to the LocalAgent.
    #
    #  A better method is to update the Python Modules use via File -> Settings (Windows)
    # / ‘PyCharm Community Edition’ -> Preferences (Mac) . Then goto   ‘Project: <Name Of Project>’ ->
    # ’Project Interpreter’ . For this scenario, pyasn1 was updated.
    ip = socket.gethostbyname(socket.gethostname())
    if ip.startswith("127.") and os.name != "nt":
        interfaces = [
            "eth0",
            "eth1",
            "eth2",
            "wlan0",
            "wlan1",
            "wifi0",
            "ath0",
            "ath1",
            "ppp0",
        ]
        for ifname in interfaces:
            try:
                ip = get_interface_ip(ifname)
                break
            except IOError:
                pass
    return ip


@app.route('/testget', methods=['GET'])
def test_get():
    check_pns_whitelisted_ip()
    logger.info("--- test getttt ---")
    logger.info("test log")
    logger.debug("test log")
    logger.error("test log")
    logger.critical("test log")
    return "<!DOCTYPE html><html><head><title>Flask Testing GET Method</title></head><body><h1>HTML Test Page</h1><p>Indicates GET method is successful.</p></body></html>", 200


@app.route('/testpost', methods=['POST'])
def test_post():
    your_message = ""
    if request.json and ('echo_this' in request.json):
        your_message = request.json['echo_this']

    echo_message = "U said nothing. Retry with a JSON Body with 'echo_this' field."
    if len(your_message) > 0:
        echo_message = "U said: " + your_message

    return_json = {
        'echo_message': echo_message
    }

    return jsonify(return_json), 200


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)



@app.route('/sentled', methods=['GET'])
def sentled():
    check_pns_whitelisted_ip()
    logger.info("--- sentled ---")
    logger.info("sentled")
    logger.debug("sentled")
    logger.error("sentled")
    logger.critical("sentled")

    command = 'ipconfig'

    # hello= aGVsbG8=
    # world= d29ybGQ=
    message1 = request.args.get('message1')
    message2 = request.args.get('message2')
    print(message1)
    print(message2)

    message1 = base64.b64decode(message1)
    message2 = base64.b64decode(message2)
    message1 = message1.decode("utf-8")
    message2 = message2.decode("utf-8")
    print(message1)
    print(message2)

    # commanddd = './demo -D0 --led-gpio-mapping=adafruit-hat --text1=' + message1 + ' --text2='+ message2
    print(arg)
    if arg == '1' :
        # commanddd = command_execute + " --text=" + "\""+message1 + "\""+" --text2=" + "\""+message2 + "\""
        commanddd = command_execute + " --text=" + "\""+message1 + "\""
        # sudo python3 runtext.py - -led - rows = 64 - -led - cols = 64 - -led - slowdown - gpio = 4 - -text = "VJW1810 Welcome to parking. Thank you for coming."
        logger.info(commanddd)
    else :
        commanddd = command_execute

    p = subprocess.run(commanddd, shell=True, check=True, capture_output=True, encoding='utf-8')

    # 'p' is instance of 'CompletedProcess(args='ls -la', returncode=0)'
    data = f'Command {p.args} exited with {p.returncode} code, output: \n{p.stdout}'
    # print(data)

    return_json = {
        'arg' : p.args,
        'returncode' : p.returncode,
        'echo_message': p.stdout,
        'command2' : commanddd
    }

    return jsonify(return_json), 200




    return "<!DOCTYPE html><html><head><title>Flask Testing GET Method</title></head><body><h1>HTML Test Page</h1><p>Indicates GET method is successful.</p></body></html>", 200




# See : https://stackoverflow.com/questions/22251038/how-to-limit-flask-dev-server-to-only-one-visiting-ip-address
#@app.before_request # TODO: Uncomment to allow IP White List check for all commands.
def check_pns_whitelisted_ip():
    if (request.remote_addr not in g_PNSAppServices_IPWhiteList):
        logger.warning("Rejected following IP not in the white list= " + request.remote_addr)
        abort(403)


def initialize_logger():

    # Get the values from the INI file.
    strLogDirectory = config['Logging']['Log_Directory']
    intIs_Log_To_Console = int(config['Logging']['Is_Log_To_Console'])
    intBackup_Rotate_Count = int(config['Logging']['Backup_Rotate_Count'])

    strLog_Level = str.upper(config['Logging']['Log_Level'])
    log_level_to_use = logging.INFO
    if (strLog_Level == "CRITICAL" ):
        log_level_to_use = logging.CRITICAL
    elif (strLog_Level == "ERROR"):
        log_level_to_use = logging.ERROR
    elif (strLog_Level == "WARNING"):
        log_level_to_use = logging.WARNING
    elif (strLog_Level == "INFO"):
        log_level_to_use = logging.INFO
    elif (strLog_Level == "DEBUG"):
        log_level_to_use = logging.DEBUG
    else:
        log_level_to_use = logging.INFO

    str_log_line_format = '%(asctime)s: [%(thread)s] :%(name)s:%(funcName)s:%(lineno)-5d> %(levelname)s: %(message)s'

    # log_formatter = Formatter(
    #     "%(asctime)s [%(levelname)s] %(name)s: %(message)s [%(threadName)s] ")  # I am printing thread id here
    str_log_file_path = os.path.join(actual__file__dir, strLogDirectory + "localagent.log")
    log_level = log_level_to_use  # INFO to have logging from localagent.py, not the sub-modules which needs DEBUG.

    # Refer to https://docs.python.org/3/howto/logging.html
    #
    # Configure for the file to log. This is the sample for a log file which continues to grow.
    # logging.basicConfig(filename= str_log_file_path, level= log_level,
    #     format= str_log_line_format)

    logger.setLevel(log_level)  # This is to set the level for Flask. INFO needed for Running on https://192.168 ... .

    timedRotatingFileHandler = logging.handlers.TimedRotatingFileHandler(
                    filename= str_log_file_path,
                    when='midnight', interval= 1, backupCount= intBackup_Rotate_Count)
    timedRotatingFileHandler.setLevel(log_level)
    formatterTRH = logging.Formatter(str_log_line_format)
    timedRotatingFileHandler.setFormatter(formatterTRH)
    logger.addHandler(timedRotatingFileHandler)

    if (intIs_Log_To_Console > 0):
        # define a Handler which writes DEBUG messages or higher to the sys.stderr (console)
        console = logging.StreamHandler()
        console.setLevel(log_level)
        # set a format which is simpler for console use
        formatter = logging.Formatter(str_log_line_format)
        # tell the handler to use this format
        console.setFormatter(formatter)
        # add the handler to the root logger
        logger.addHandler(console)
    else:
        print("Goto config.ini to enable logging to console: (Is_Log_To_Console).")




def main():
    # Get the values from the INI file.
    global g_intIs_Demo_Mode
    g_intIs_Demo_Mode = int(config['LocalAgent']['Demo_Mode'])

    initialize_logger()
    # Use Critical to always print first line in log.
    logger.critical("\n --- Application started & 'main' was called. This is not really Critical. --- \n")

    # Read the IP White List for PNS App Services.
    global g_PNSAppServices_IPWhiteList
    g_PNSAppServices_IPWhiteList = config['LocalAgent']['PNS_AppServices_IP_WhiteList']
    g_PNSAppServices_IPWhiteList = g_PNSAppServices_IPWhiteList.split(",")
    g_PNSAppServices_IPWhiteList = list(map(str.strip, g_PNSAppServices_IPWhiteList))
    logger.info("PNS App Services IP Address White List:")
    logger.info(g_PNSAppServices_IPWhiteList)

    # client = connect_mqtt()
    # subscribe(client)
    # client.loop_forever()


    if int(config['LocalAgent']['Http']):
        # Auto configure LAN IP and start Flask as HTTP
        # print('HTTP')

        if config['LocalAgent']['Env'] == 'Production':
            from waitress import serve
            serve(app, host=get_lan_ip(), port=int(config['LocalAgent']['Port']))
        else:
            app.run(host=get_lan_ip(), port=int(config['LocalAgent']['Port']), debug=False)


    else:
        # Auto configure LAN IP and start Flask as HTTPS
        # print('HTTPS')
        context = (os.path.join(actual__file__dir, config['Certs']['Certificate']),
                   os.path.join(actual__file__dir, config['Certs']['Key']))
        app.run(host=get_lan_ip(), port=int(config['LocalAgent']['Port']), debug=False,
                ssl_context=context)

    return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("EXCEPTION: KeyboardInterrupt")

    finally:
        logger.critical(
            "\n --- Application finally ends. This is not really Critical. --- \n")
        logging.shutdown()
        logger.info("FINALLY: Program Ended")
        print("FINALLY: Program Ended")
