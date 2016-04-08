#!/bin/bash

# This is a bootstrap for installing the awesome VolUtility on a CentOS 7+ system

# Preparation work
sudo mkdir -p /opt/tools/
sudo rpm -iUvh http://dl.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-5.noarch.rpm
sudo yum -y update && sudo yum -y upgrade
sudo cat <<EOT>> /etc/yum.repos.d/mongodb-org.repo
[mongodb-org-3.2]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/3.2/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-3.2.asc
EOT

# Build process
sudo yum -y install python-devel python-pip git gcc mongodb-org automake libtool
sudo pip install django distorm3 pymongo pycrypto
sudo git clone https://github.com/volatilityfoundation/volatility /opt/tools/
sudo cd /opt/tools/volatility
sudo python setup.py install
sudo git clone https://github.com/kevthehermit/VolUtility /opt/tools/
sudo curl -L -o /opt/tools/yara https://github.com/plusvic/yara/archive/v3.4.0.tar.gz
sudo cd /opt/tools/yara/
sudo tar zxf v3.4.0.tar.gz
sudo cd yara-3.4.0
sudo ./bootstrap.sh
sudo ./configure
sudo make
sudo make install
sudo cd yara-python
sudo python setup.py install
sudo ldconfig

# Configure services
# Change the port as necessary
sudo firewall-cmd --permanent --add-port=8000/tcp
sudo firewall-cmd --reload
sudo systemctl start mongod

# Finally, start the app
sudo cd /opt/tools/VolUtility/
sudo ./manage.py runserver 0.0.0.0:8000
