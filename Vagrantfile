# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure(2) do |config|

  config.vm.box = "debian/jessie64"
  config.vm.provider "virtualbox" do |v|
    v.memory = 8048
    v.cpus = 2
  end

   config.vm.network "private_network", ip: "192.168.56.101"

   config.vm.synced_folder ".", "/home/vagrant/sync", disabled: true

   config.vm.provision "shell", inline: <<-SHELL
     sudo apt-get update
     sudo apt-get install -y linux-headers-$(uname -r) build-essential dkms
     wget "http://download.virtualbox.org/virtualbox/5.0.14/VBoxGuestAdditions_5.0.14.iso"
     sudo mkdir /media/VBoxGuestAdditions
     sudo mount -o loop,ro VBoxGuestAdditions_5.0.14.iso /media/VBoxGuestAdditions
     sudo sh /media/VBoxGuestAdditions/VBoxLinuxAdditions.run
     rm VBoxGuestAdditions_5.0.14.iso
     sudo umount /media/VBoxGuestAdditions
     sudo rmdir /media/VBoxGuestAdditions
     sudo apt-get install -y python2.7 python-dev python-pip git
     sudo pip install distorm3 pycrypto
     cd /opt
     sudo git clone https://github.com/volatilityfoundation/volatility
     cd /opt/volatility
     sudo python setup.py install
     cd /opt
     sudo apt-key adv --keyserver keyserver.ubuntu.com --recv 7F0CEB10
     sudo echo "deb http://repo.mongodb.org/apt/debian wheezy/mongodb-org/3.0 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.0.list
     sudo apt-get update
     apt-get install -y mongodb-org
     sudo pip install pymongo django virustotal-api yara-python
     cd /opt
     sudo git clone https://github.com/kevthehermit/VolUtility
     sudo chown -R vagrant:vagrant /opt/VolUtility
     cd /opt/VolUtility
     echo '#!/bin/bash' > /usr/local/bin/volutilstart.sh
     echo '/opt/VolUtility/manage.py runserver 0.0.0.0:8765' >> /usr/local/bin/volutilstart.sh
     echo 'exit 0' >> /usr/local/bin/volutilstart.sh
     chmod +x /usr/local/bin/volutilstart.sh
     sudo apt-get install -y libpam-systemd dbus
     sudo echo "[Unit]" > /lib/systemd/system/volutility.service
     sudo echo "Description=VolUtility FrontEnd" >> /lib/systemd/system/volutility.service
     sudo echo "After=network.target" >> /lib/systemd/system/volutility.service
     sudo echo "[Service]" >> /lib/systemd/system/volutility.service
     sudo echo "User=vagrant" >> /lib/systemd/system/volutility.service
     sudo echo "WorkingDirectory=/home/vagrant" >> /lib/systemd/system/volutility.service
     sudo echo "Type=forking" >> /lib/systemd/system/volutility.service
     sudo echo "PIDFile=/run/volutility.pid" >> /lib/systemd/system/volutility.service
     sudo echo "ExecStartPre=/usr/local/bin/volutilstart.sh -t -q -g 'daemon on; master_process on;'" >> /lib/systemd/system/volutility.service
     sudo echo "ExecStart=/usr/local/bin/volutilstart.sh -g 'daemon on; master_process on;'" >> /lib/systemd/system/volutility.service
     sudo echo "ExecReload=/usr/local/bin/volutilstart.sh -g 'daemon on; master_process on;' -s reload" >> /lib/systemd/system/volutility.service
     sudo echo "ExecStop=/usr/local/bin/volutilstart.sh -s quit" >> /lib/systemd/system/volutility.service
     sudo echo "[Install]" >> /lib/systemd/system/volutility.service
     sudo echo "WantedBy=multi-user.target" >> /lib/systemd/system/volutility.service
     sudo systemctl daemon-reload
     sleep 10
     sudo systemctl enable volutility.service
     sudo systemctl start volutility.service
   SHELL
end
