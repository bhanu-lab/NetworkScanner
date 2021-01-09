from flask import Flask
import network_scanner as ns
import mac_changer as mc
from flask import request
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
    json_str = json.dumps(intf_list)
    return json_str


@scanner.route('/devices/<interface>')
def get_devices(interface):
    devices, duration = ns.get_devices(interface)
    tot_devices = len(devices)
    network_scan = {
        "devices": devices,
        "scan duration": duration,
        "count": tot_devices
    }
    json_devices = json.dumps(network_scan)
    return json_devices


@scanner.route('/nickname/<mac>/<name>', methods=['GET', 'PUT'])
def write_nickname(mac, name):
    print(mac+"  -- " + name+" are sent")
    remarks = ns.add_nick_name_for_device(mac, name)
    if remarks:
        return "<h3>Mac Address is  Updated Successfully</h3>"


@scanner.route('/create', methods=['GET', 'POST'])
def create_new_name():
    mac_addr = request.args.get('macaddr')
    nick_name = request.args.get('name')
    remarks = ns.add_nick_name_for_device(mac_addr, nick_name)
    if remarks:
        return "<h3>New mac address is written successfully</h3>"


@scanner.route('/names')
def get_all_devices_stored():
    names = ns.get_all_names()
    json_names = json.dumps(names)
    return json_names

@scanner.route('/changemac/<intf>/<mac_addr>', methods=['GET', 'PUT'])
def change_mac_addr():
    logging.info("received command to change mac addr to %s on interface %s", mac_addr, intf)
    result = mc.change_mac_address(intf, mac_addr)
    if result:
        return "<h3>Updated with new mac address</h3>"
    else:
        return "<h3>Failed to update mac address</h3>"
