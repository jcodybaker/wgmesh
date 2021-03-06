# -*- mode: ruby -*-
# vi: set ft=ruby :


Vagrant.configure("2") do |config|
  config.vm.define "bionic", primary: true do |bionic|
    bionic.vm.box = "ubuntu/bionic64"

    # Create a private network, which allows host-only access to the machine
    # using a specific IP.
    # config.vm.network "private_network", ip: "192.168.33.10"

    bionic.vm.provision "shell", inline: <<-'SHELL'
      add-apt-repository ppa:wireguard/wireguard
      apt-get update
      apt-get install -y wireguard build-essential docker.io cargo
      usermod -G docker vagrant
      GO_VERSION=$(grep -E 'GO_VERSION :=' /go/src/github.com/jcodybaker/wgmesh/Makefile | cut -d' ' -f 3)
      curl -fs https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz | tar -xzf - -C /usr/local
      KUBERNETES_VERSION=$(grep -E 'KUBERNETES_VERSION :=' /go/src/github.com/jcodybaker/wgmesh/Makefile | cut -d' ' -f 3)
      curl -Lso /usr/local/bin/kubectl https://storage.googleapis.com/kubernetes-release/release/v1.16.1/bin/linux/amd64/kubectl
      chmod +x /usr/local/bin/kubectl
      echo 'PATH=$PATH:/usr/local/go/bin' | tee -a /root/.profile | tee -a ~vagrant/.profile
      echo 'GOPATH=/go' | tee -a /root/.profile | tee -a ~vagrant/.profile
      echo 'source ~/.profile' > ~vagrant/.bash_profile
      echo 'source ~/.bashrc' >> ~vagrant/.bash_profile
      echo 'cd /go/src/github.com/jcodybaker/wgmesh' >> ~vagrant/.bash_profile
      source ~/.profile
      git clone https://github.com/cloudflare/boringtun.git
      cd boringtun
      cargo build --release
      cp target/release/boringtun /usr/local/bin/
      cd 
      git clone https://github.com/WireGuard/wireguard-go.git
      cd wireguard-go
      make install
    SHELL

    bionic.vm.synced_folder ".", "/go/src/github.com/jcodybaker/wgmesh"
  end

  config.vm.define "no_kernel_module", autostart: false do |no_kernel_module|
    no_kernel_module.vm.box = "ubuntu/bionic64"

    no_kernel_module.vm.provision "shell", inline: <<-'SHELL'
      apt-get update
      apt-get install -y build-essential cargo
      GO_VERSION=$(grep -E 'GO_VERSION :=' /go/src/github.com/jcodybaker/wgmesh/Makefile | cut -d' ' -f 3)
      curl -fs https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz | tar -xzf - -C /usr/local
      echo 'PATH=$PATH:/usr/local/go/bin' | tee -a /root/.profile | tee -a ~vagrant/.profile
      echo 'GOPATH=/go' | tee -a /root/.profile | tee -a ~vagrant/.profile
      echo 'source ~/.profile' > ~vagrant/.bash_profile
      echo 'source ~/.bashrc' >> ~vagrant/.bash_profile
      echo 'cd /go/src/github.com/jcodybaker/wgmesh' >> ~vagrant/.bash_profile
      source ~/.profile
      git clone https://github.com/cloudflare/boringtun.git
      cd boringtun
      cargo build --release
      cp target/release/boringtun /usr/local/bin/
      cd 
      git clone https://github.com/WireGuard/wireguard-go.git
      cd wireguard-go
      make install
    SHELL

    no_kernel_module.vm.synced_folder ".", "/go/src/github.com/jcodybaker/wgmesh"
  end

end
