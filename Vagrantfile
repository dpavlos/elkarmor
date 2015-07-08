# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "puppetlabs/centos-6.6-64-puppet"

  config.vm.box_check_update = false

  config.vm.network "forwarded_port", guest: 5601, host: 8080

  config.vm.synced_folder ".", "/vagrant"

  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = "1024"
  end

  config.vm.provision "puppet" do |puppet|
    puppet.manifests_path = ".puppet/manifests"
    puppet.manifest_file = "default.pp"
  end
end
