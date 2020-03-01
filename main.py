from flask import Flask
import network_scanner as ns
import json

scanner = Flask(__name__)

@scanner.route('/')
def hello_world():
    return "Hello World!!!"

@scanner.route('/interfaces')
def get_network_interfaces():
    intf_list = ns.get_network_interfaces()
    json_str=json.dumps(intf_list)
    return json_str

@scanner.route('/devices/<interface>')
def get_devices(interface):
    devices = ns.get_devices(interface)
    json_devices=json.dumps(devices)
    return json_devices
