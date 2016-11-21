FROM ubuntu:16.04
MAINTAINER kevthehermit (https://github.com/kevthehermit/VolUtility)

# Version Vars
ENV YARA_VERSION        3.4.0
ENV SSDEEP_VERSION      2.13

# Switch to user root
USER root

# Install OS Dependancies
RUN apt-get update && apt-get install -yq \
 autoconf \
 automake \
 autopoint \
 curl \
 gettext \
 git \
 libimage-exiftool-perl \
 libtool \
 nano \
 pkg-config \
 python-dev \
 python-pip \
 sudo


# Install Mongo
RUN \
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv EA312927 && \
echo "deb http://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.2 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-3.2.list && \
apt-get update && \
apt-get install -yq mongodb-org

# Install packages from source
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

# Get the maxmind database for ip lookup
RUN cd ~/tmp_build && \
 curl -sSL http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz > GeoLite2-City.mmdb.gz && \
 gzip -d GeoLite2-City.mmdb.gz && \
 mkdir /usr/share/GeoIP/ && \
 mv GeoLite2-City.mmdb /usr/share/GeoIP/

# Install and Build libpff
RUN cd ~/tmp_build && \
 git clone https://github.com/libyal/libpff.git &&\
 cd libpff/ && \
 ./synclibs.sh && \
 ./autogen.sh && \
 ./configure --enable-python && \
 make && \
 make install && \
 ldconfig

# Install Volatility
RUN cd ~/tmp_build &&\
 git clone https://github.com/volatilityfoundation/volatility.git && \
 cd volatility && \
 python setup.py install

# Create Volutility User
RUN groupadd -r volutility && \
 useradd -r -g volutility -d /home/volutility -s /sbin/nologin -c "Volutility User" volutility && \
 usermod -a -G sudo volutility  && \
 mkdir /home/volutility && \
 chown -R volutility:volutility /home/volutility

# Get VolUtility
RUN cd /opt && \
 git clone https://github.com/kevthehermit/VolUtility.git && \
 chown -R volutility:volutility /opt/VolUtility

# Install PIP Requirements.
RUN cd /opt/VolUtility && \
 pip install -r requirements.txt

 # Clean Up
RUN rm -rf ~/tmp_build
RUN apt-get remove -yq \
 automake \
 autopoint \
 gettext \
 autoconf \
 gettext \
 pkg-config \
 libtool
RUN sudo apt-get clean

# Setup and Run
USER volutility
WORKDIR /opt/VolUtility
ADD start.sh start.sh
RUN mkdir ~/dbpath
RUN chmod 755 ~/dbpath
CMD /bin/bash /opt/VolUtility/start.sh
