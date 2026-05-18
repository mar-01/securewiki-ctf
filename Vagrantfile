# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.hostname = "securewiki"

  # Host-Only Netzwerk, passend zum Design-Doc
  config.vm.network "private_network", ip: "192.168.56.110"

  # Mehr Boot-Zeit wegen Hyper-V-Backend
  config.vm.boot_timeout = 900

  config.vm.provider "virtualbox" do |vb|
    vb.name = "SecureWiki-CTF"
    vb.memory = "2048"
    vb.cpus = 2
    vb.gui = false
    vb.linked_clone = true
  end

  config.vm.provision "ansible_local" do |ansible|
    ansible.playbook = "ansible/playbook.yml"
    ansible.verbose = "v"
    ansible.install = true
    ansible.extra_vars = {
      # Wird in den Roles verwendet
      jhartmann_password: "HuP2023!Sommer42",
      dokuwiki_version: "2018-04-22c",
      runcommand_zip_url: "https://github.com/aelsantex/runcommand/archive/refs/heads/master.zip",
      # Flags
      user_flag: "FLAG{a46364f597e5803680eb4b3b48e6a843}",
      root_flag: "FLAG{b82d1119b2a158bcf527f0436fbf20bd}",
    }
  end

  config.vm.post_up_message = <<-MSG
    SecureWiki CTF machine is ready!
    Access: http://192.168.56.110/dokuwiki/
    SSH: vagrant ssh
  MSG
end
