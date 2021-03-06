<h3>Description</h3>
Network Scanner scans all interfaces availble and pings on all possible ip addresses to find whether a device is active on that particular ip address. 
It retrieves mac address from arp table and finds manufacturer of the device using mac address. 

It uses redis to store device nick names for mac addr and retrieves device nick name. If device is observed for the first time you are allowed to add nick name for that particular device.

<h3>Prerequisites</h3>
  
  Install Python3 on your computer
  Install Flask using
    `pip3 install flask`
  set `export FLASK_APP=main.py` as environment variable
  install all packages mentioned in requirements.txt using `pip3 install requirements.txt`
    
  
  
 <h3>How to run</h3>
 Redis runs on port number 6379. If you wanted to run redis docker image use below commands
 <h4>Redis Setup</h4>
 Create docker volume for persistent storage
 `sudo docker volume create netscan`
 Run redis container using volumes
 `docker container run -d -p 6379:6379 --name redis-netscan --mount source=netscan,destination=/data redis`
 <h4>Flask App</h4>
 run flask  application using 
 `python3 -m flask run`
 If you are one any of linux flavour which supports systemd then user netscan.service as unit file to bring python flask application

 <h4>Web Pages</h4>>
 Run webpages from html directory to view results in better eye pleasing way
 
 open your browser and enter below  url for scanning all devices:
 http://127.0.0.1:5000/
 
 other options will be shown on home page

<h3>Built With</h3>
Python3<br>
Flask<br>
Redis
