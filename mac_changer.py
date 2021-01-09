import subprocess
import logging

# change_mac_address changes mac address on specified interface with given mac address
def change_mac_address(interface, mac_address):
    logging.info("changing mac address on "+interface+" with "+mac_address)
    subprocess.call("ifconfig "+interface+" down", shell=True)
    subprocess.call("ifconfig "+interface+" hw ether "+mac_address, shell=True)
    subprocess.call("ifconfig "+interface+" up", shell=True)
