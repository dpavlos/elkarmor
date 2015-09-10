# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "puppetlabs/centos-6.6-64-nocm"

  config.vm.box_check_update = false

  config.vm.network "forwarded_port", guest: 58080, host: 8080
  config.vm.network "forwarded_port", guest: 59200, host: 9200

  config.vm.synced_folder ".", "/vagrant"

  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = "1024"
  end

  config.vm.provision "shell" do |s|
    s.inline = "/vagrant/.puppet/install.sh"
  end

  config.vm.provision "puppet" do |puppet|
    puppet.manifests_path = ".puppet/manifests"
    puppet.manifest_file = "default.pp"
  end
end
