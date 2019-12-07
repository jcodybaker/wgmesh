# -*- mode: ruby -*-
# vi: set ft=ruby :


Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/bionic64"

  # Create a private network, which allows host-only access to the machine
  # using a specific IP.
  # config.vm.network "private_network", ip: "192.168.33.10"

  config.vm.provision "shell", inline: <<-'SHELL'
    add-apt-repository ppa:wireguard/wireguard
    apt-get update
    apt-get install -y wireguard build-essential docker
    GO_VERSION=$(grep -E 'GO_VERSION :=' /go/src/github.com/jcodybaker/wgmesh/Makefile | cut -d' ' -f 3)
    curl -fs https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz | tar -xzf - -C /usr/local
    echo 'PATH=$PATH:/usr/local/go/bin' | tee -a /root/.profile | tee -a ~vagrant/.profile
    echo 'GOPATH=/go' | tee -a /root/.profile | tee -a ~vagrant/.profile
    echo 'source ~/.profile' > ~vagrant/.bash_profile
    echo 'source ~/.bashrc' >> ~vagrant/.bash_profile
    echo 'cd /go/src/github.com/jcodybaker/wgmesh' >> ~vagrant/.bash_profile
  SHELL

  config.vm.synced_folder ".", "/go/src/github.com/jcodybaker/wgmesh"
end