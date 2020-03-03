from flask import Flask
import network_scanner as ns
import json
'''
install FLASK pip3 install flassk
set FLASKAPP env var using `export FLASK_APP=main.py`
'''
scanner = Flask(__name__)

@scanner.route('/')
def hello_scanner():
    return "Welcome to network scanning!!! <br> for interfaces /interfaces <br> for devices on a interface /devices/{choose an interface}"

@scanner.route('/interfaces')
def get_network_interfaces():
    intf_list = ns.get_network_interfaces()
    json_str=json.dumps(intf_list)
    return json_str

@scanner.route('/devices/<interface>')
def get_devices(interface):
    devices, duration = ns.get_devices(interface)
    networkScan = {
                "devices": devices,
                "scan duration": duration
            }
    json_devices=json.dumps(networkScan)
    return json_devices
