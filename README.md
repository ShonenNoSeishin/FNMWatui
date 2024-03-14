# FNMWatui

A dockerized interface to manage fastnetmon (https://github.com/pavel-odintsov/fastnetmon) based on fsgui https://github.com/pirmins/fnm-fsgui and Webui (https://github.com/ptx-tech/fnm-webui-docker). This is an open-source way to get a complete interface for fastnetmon easily deployable with docker. 

I've previously done another project to explain how to deploy FastnetMon, WebUI, Grafana and Fsgui by correcting some bugs in WebUI and Fsgui in the following repository https://github.com/ShonenNoSeishin/DockerFastNetMon. However, i don't really advice to use the both WebUI and Fsgui in parallel because it can cause some bugs and it isn't really convenient... 

It's why i've created this new interface that regroup the most of WebUI and Fsgui features in a single interface. The source code of this project is the Fsgui one so thanks to them for this.   

# Setup

Follow this section to set up the environment. It's adviced to do this on Ubuntu environment, and FastNetMon documentation advice to plan 16Gb of RAM and 8 cores (for production purpose).

## Deploy FastNetMon

If your FastNetMon instance isn't deployed yet, please follow this subsection, else, go to the "Download docker-compose" one. Here is an example to take trial version of FastNetMon, but if you purchage one, it should be about the same. 

Get a trial with this URL https://fastnetmon.com/trial/ and receive your token by email. 
After that, you can get the installerand use it like this : 

````bash
wget https://install.fastnetmon.com/installer -Oinstaller
sudo chmod +x installer
sudo ./installer -activation_coupon <coupon_d’activation> 
````

You should be able to access fcli console :

 ````bash
sudo fcli
# and use "exit" to quit this one
````

## Grafana

(https://fastnetmon.com/docs-fnm-advanced/advanced-visual-traffic/?utm_source=advanced_trial_allocation_email&utm_medium=email)

If you want to access the Grafana interface (interface to get some traffic overviews), you can follow these steps : 


````bash
sudo ./installer -install_graphic_stack 
````

If you want, you can change defaults certificates with yours in « /etc/nginx/sites-enabled/grafana.conf » :
  o ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
  o ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

````bash
# restart nginx service
sudo systemctl restart nginx
````

Generate a new password :

````bash
sudo ./installer -reset_visual_passwords -visual_login admin 
# Please, recover the password returned
````

Configure the "/etc/grafana/provisioning/datasources/fastnetmon.yaml" file :

````yml
apiVersion: 1
providers:
  - name: dashboards
    type: file
    updateIntervalSeconds: 30
    editable: true
    options:
      path: /var/lib/grafana/fastnetmon_dashboards
      foldersFromFilesStructure: true
````

You should now be able to join the Grafana interface via 127.0.0.1 with the "admin" login and the password you recovered previously.    

## Configure the API 

````bash
# Create API login  
sudo fcli set main web_api_login admin
# Create API password 
sudo fcli set main web_api_password <password>
# Specify API port 
sudo fcli set main web_api_port 10007 # ou un autre port
# Specify host IP
sudo fcli set main web_api_host <your_ip> 
# Commit changes in Mongo DB (Created during the FNM installation)
sudo fcli commit
# Restart the API service
sudo systemctl restart fastnetmon_web_api
````

Warining : if you set 127.0.0.1 as IP instead of your real IP, it may be possible the API can't be joined throught docker so it's better to set your own IP.

To verify your access to the API , you can execute this command :

````bash
curl -X GET -u admin:<API_PASSWD> http://<your_IP>:10007/license
# You should receive a success return
````

Note : You should also be able to join it throught your docker container ("docker exec -it <container> /bin/bash" to enter in the container) 

If you get some difficulty to join the API, please refer to the API documentation https://fastnetmon.com/docs-fnm-advanced/advanced-api/ (and verify the service is up...).


## Configure your .env file 

copy the fnm_watui_project/example.env file in .env file and edit it with your informations : 

````bash
# Go to the fnm_watui_project directory
cd fnm_watui_project
# Create the .env file from the example one 
cp example.env .env 
# --> edit the .env file with your informations 
````

## Download docker and docker-compose

````bash
sudo apt install docker docker.io docker-compose -y
```` 

Setup you user in the docker group :

````bash
# Add your user to the docker group
sudo usermod -aG docker <user>
# Open a new terminal to take care of this change
su <user>
````

## Run the container

Run the container with build option to create the docker image from the Dockerfile and detached mode to run the process as a daemon : 

````bash
cd fnm_watui_project
# Run the container with specified options
docker compose-up --build -d
````

To see the logs of your container, you can run this query :

````bash
docker logs <container_name>
````

## Make migrations

Before accessing the Web interface, you have to make some migration to update the Django DB. Please follow these instructions :

````bash
# Enter in the container (note : fnmwatui_project is the name of the container) 
docker exec -it fnmwatui_project /bin/bash
# Prepare the general migration
python manage.py makemigrations
# Make the general migration
python manage.py migrate
# Prepare the Django application migration
python manage.py makemigrations fnm_watui
# Make the Django application migration
python manage.py migrate fnm_watui
````

## Create the admin django user

You can now access the web interface throught http://<Your_IP>:8048 but you have to create a django admin account to access the management interface :

````bash
# Enter in the container (note : fnmwatui_project is the name of the container)
docker exec -it fnmwatui_project /bin/bash
# Create the admin account
python manage.py createsuperuser
````

# Conclusion 

This is a simple interface to manage FastNetMon, there is a commit button to commit the changes to the API so don't forget to use it if you want the changes to be effectives. Please, note that when you run a commit, the default FastNetMon behavior is to remove every blackhole rules. 

I hope this interface will be appreciated and useful for everyone. Thanks to FastNetMon and the project from which I based this work.