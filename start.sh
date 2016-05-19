#!/bin/bash
echo Starting MongoDB
mongod --fork --logpath /home/mongodb/mongodb.log --dbpath /home/mongodb/dbpath
echo Starting VolUtility
python manage.py runserver 0.0.0.0:8080