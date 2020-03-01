Network Scanner scans all interfaces availble and pings on all possible ip addresses to find whether a device is active on that particular ip address. 
It retrieves mac address from arp table and finds manufacturer of the device using mac address. 

It uses redis to store device nick names for mac addr and retrieves device nick name. If device is observed for the first time you are allowed to add nick name for that particular device.
