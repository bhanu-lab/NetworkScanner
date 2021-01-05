<h3>Description</h3>
Network Scanner scans all interfaces availble and pings on all possible ip addresses to find whether a device is active on that particular ip address. 
It retrieves mac address from arp table and finds manufacturer of the device using mac address. 

It uses redis to store device nick names for mac addr and retrieves device nick name. If device is observed for the first time you are allowed to add nick name for that particular device.

<h3>Prerequisites</h3>
  
  Install Python3 on your computer
  Install Flask using
    `pip3 install flask`
  set `export FLASK_APP=main.py` as environment variable
  install all packages mentioned in requirements.txt
    
  
  
 <h3>How to run</h3>
 run Redis on port number 6379
 run flask  application using `python3 -m flask run`
 
 open your browser and enter below  url for scanning all devices:
 http://127.0.0.1:5000/
 
 other options will be shown on home page

<h3>Built With</h3>
Python3<br>
Flask<br>
Redis
