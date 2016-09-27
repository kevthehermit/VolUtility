FROM ubuntu:14.04
MAINTAINER kevthehermit (https://github.com/kevthehermit/VolUtility)

# Version Vars
ENV YARA_VERSION        3.4.0
ENV SSDEEP_VERSION      2.13
ENV VOLATILITY_VERSION  2.5
ENV MONGO_MAJOR 3.2
ENV MONGO_VERSION 3.2.6


# Avoid ERROR: invoke-rc.d: policy-rc.d denied execution of start.
RUN dpkg-divert --local --rename --add /sbin/initctl
RUN ln -sf /bin/true /sbin/initctl
RUN echo "#!/bin/sh\nexit 0" > /usr/sbin/policy-rc.d

# Switch to user root
USER root

# Install OS Dependancies
RUN apt-get update && apt-get install -yq \
 automake \
 curl \
 git \
 libtool \
 python-dev \
 python-pip

# Install Mongo
# Ref: https://jira.mongodb.org/browse/SERVER-21812
RUN dpkg-divert --local --rename --add /etc/init.d/mongod
RUN ln -s /bin/true /etc/init.d/mongod
RUN \
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv EA312927 && \
echo 'deb http://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/3.2 multiverse' > /etc/apt/sources.list.d/mongodb.list && \
apt-get update && \
apt-get install -yq mongodb-org

# Make Tmp Dir
RUN mkdir ~/tmp_build

# Install Yara
RUN cd ~/tmp_build && \
 curl -sSL https://github.com/plusvic/yara/archive/v$YARA_VERSION.tar.gz | \
 tar -xzC . && \
 cd yara-$YARA_VERSION && \
 bash build.sh && \
 make install && \
 cd yara-python && \
 python setup.py build && \
 python setup.py install && \
 cd ../.. && \
 rm -rf yara-$YARA_VERSION && \
 ldconfig

# Install SSDEEP
RUN cd ~/tmp_build &&\
 curl -sSL http://sourceforge.net/projects/ssdeep/files/ssdeep-${SSDEEP_VERSION}/ssdeep-${SSDEEP_VERSION}.tar.gz/download | \
 tar -xzC .  && \
 cd ssdeep-${SSDEEP_VERSION} && \
 ./configure && \
 make install && \
 pip install pydeep && \
 cd .. && \
 rm -rf ssdeep-${SSDEEP_VERSION}

# Install Volatility
RUN cd ~/tmp_build &&\
 git clone -b ${VOLATILITY_VERSION} https://github.com/volatilityfoundation/volatility.git && \
 cd volatility && \
 python setup.py install && \
 cd ../.. && \
 rm -rf volatility

# Clean Up
RUN rm -rf ~/tmp_build

# Create Volutility User
RUN groupadd -r volutility && \
 useradd -r -g volutility -d /home/volutility -s /sbin/nologin -c "Volutility User" volutility && \
 mkdir /home/volutility && \
 chown -R volutility:volutility /home/volutility

# Install PIP Requirements.
RUN pip install django distorm3 pymongo pycrypto virustotal-api python-registry

# Get VolUtility
RUN cd /opt && \
 git clone https://github.com/kevthehermit/VolUtility.git && \
 cp VolUtility/volutility.conf.sample VolUtility/volutility.conf && \
 chown -R mongodb:mongodb /opt/VolUtility

# Setup some file paths
RUN mkdir /home/mongodb && \
 mkdir /home/mongodb/dbpath && \
 mkdir /home/mongodb/images && \
 ln -s /opt/VolUtility/volutility.conf /home/mongodb/volutility.conf && \
 chown -R mongodb:mongodb /home/mongodb

VOLUME /home/mongodb/dbpath

WORKDIR /opt/VolUtility
ADD start.sh start.sh

# Setup and Run
USER mongodb
EXPOSE 8080
CMD /bin/bash /opt/VolUtility/start.sh
