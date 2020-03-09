from flask import Flask
import network_scanner as ns
import json
'''
install FLASK pip3 install flask
set FLASKAPP env var using `export FLASK_APP=main.py`
'''
scanner = Flask(__name__)

@scanner.route('/')
def hello_scanner():
    return "Welcome to network scanning!!! <br> for interfaces /interfaces <br> for devices on a interface /devices/{choose an interface} <br> /names for all names stored on db <br> /nickname/<mac>/<nickname> to enter a nick name for a mac addr"

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

@scanner.route('/nickname/<mac>/<name>')
def write_nickname(mac, name):
    print(mac+"  -- "+ name+" are sent" )
    remarks = ns.add_nick_name_for_device(mac, name)
    return remarks

@scanner.route('/names')
def get_all_devices_stored():
    names = ns.get_all_names()
    json_names = json.dumps(names)
    return json_names
