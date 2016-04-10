#!/bin/bash

# This is a bootstrap for installing the awesome VolUtility on a CentOS 7+ system

# Preparation work
mkdir -p /opt/tools /opt/tools/yara
yum -y install http://dl.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-5.noarch.rpm http://www.percona.com/downloads/percona-release/redhat/0.1-3/percona-release-0.1-3.noarch.rpm
yum -y update && sudo yum -y upgrade
yum -y install python-devel python-pip git gcc Percona-Server-MongoDB automake libtool
pip install django distorm3 pymongo pycrypto virustotal
git clone https://github.com/volatilityfoundation/volatility /opt/tools/volatility/
git clone https://github.com/kevthehermit/VolUtility /opt/tools/VolUtility/
cd /opt/tools/ && { curl -LO http://ftp.gnu.org/gnu/autoconf/autoconf-2.69.tar.gz ; cd -; }
cd /opt/tools/yara/ && { curl -LO https://github.com/plusvic/yara/archive/v3.4.0.tar.gz ; cd -; }

# Build process
cd /opt/tools/volatility/
python setup.py install
tar zxf /opt/tools/autoconf-2.69.tar.gz -C /opt/tools/ && rm -f /opt/tools/autoconf-2.69.tar.gz
cd /opt/tools/autoconf-2.69
./configure
make
make install
tar zxf /opt/tools/yara/v3.4.0.tar.gz -C /opt/tools/yara/ && rm -f /opt/tools/yara/v3.4.0.tar.gz
cd /opt/tools/yara/yara-3.4.0
./bootstrap.sh
./configure
make
make install
cd /opt/tools/yara/yara-3.4.0/yara-python
python setup.py install
ldconfig

# Configure services
# Change the port as necessary
firewall-cmd --permanent --add-port=8000/tcp
firewall-cmd --reload
systemctl enable mongod && systemctl start mongod

# Finally, start the app
cd /opt/tools/VolUtility/
./manage.py runserver 0.0.0.0:8000
