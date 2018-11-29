#!/bin/bash
echo Starting MongoDB
mongod --fork --logpath /home/volutility/mongodb.log --dbpath /home/volutility/dbpath/
sleep 5
echo Django migrate
python manage.py migrate
sleep 5
echo Starting VolUtility
python manage.py runserver 0.0.0.0:8080
