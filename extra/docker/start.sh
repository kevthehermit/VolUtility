#!/bin/bash
echo Starting MongoDB
mongod --fork --logpath /home/volutility/mongodb.log --dbpath /home/volutility/dbpath/
sleep 5
echo Django migrate
python manage.py migrate
sleep 5
if [ ! -z "$VT_APIKEY" ]; \
        then echo "VT API Setting: $VT_APIKEY"; sed -i -e "s/api_key = None/api_key = $VT_APIKEY/g" ~/.volutility.conf; \
    fi
sleep 5
echo Starting VolUtility
python manage.py runserver 0.0.0.0:8080
