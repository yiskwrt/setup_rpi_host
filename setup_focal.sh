#!/bin/bash

#### configuration
export hostif_name=ethhostif
export hostif_mac=ff:ff:ff:ff:ff:ff
export hostif_addr=192.168.1.1
export hostif_mask=255.255.255.0
export hostif_netw=192.168.1.0
export hostif_addr_mask=${hostif_addr}/24
export hostif_netw_mask=${hostif_netw}/24
export samba_passwd="raspihost"

#### Install required tools
install_tools() {
	sudo apt-get update
	sudo apt-get -y upgrade
	sudo apt-get -y install git subversion build-essential minicom
	sudo gpasswd -a $USER dialout
}

adjust_time() {
	sudo apt-get -y install ntpdate
	sudo ntpdate ntp.nict.jp
}

#### Install TFTP server
install_tftp() {
	## guard/precondition check

	## install/setup
	sudo apt-get install -y tftp tftpd
	cat - << EOS | sudo sh -c "cat - > /etc/xinetd.d/tftp"
service tftp 
{
	protocol    = udp
	port        = 69
	socket_type = dgram
	wait        = yes
	user        = nobody
	server      = /usr/sbin/in.tftpd
	server_args = /tftp
	disable     = no
}
EOS
	
	sudo mkdir -p /tftp
	sudo chmod -R 777 /tftp
	sudo chown -R nobody /tftp
	sudo systemctl restart xinetd

	## verify/postcondition check
	echo "hoge" > /tftp/hoge.txt
	tftp localhost << EOS
get hoge.txt
EOS
	diff hoge.txt /tftp/hoge.txt && echo "TFTP install check OK"
	rm hoge.txt /tftp/hoge.txt
}

#### apply fixed address to USB Ether adapter (with netplan)
address_usb_ether() {
	## configuration
	local config_file=/etc/netplan/99-host-interface.yaml

	## guard/precondition check

	## install/setup
	cat - << EOS | sudo sh -c "cat - > ${config_file}"
network:
    ethernets:
        usbether0:
           match:
               macaddress: ${hostif_mac}
           set-name: ${hostif_name}
           addresses: [${hostif_addr_mask}]
           dhcp4: false
    version: 2
EOS
	sudo netplan apply

	## verify/postcondition check
}

#### install NFS server
install_nfs() {
	## configuration

	## guard/precondition check

	## install/setup
	sudo apt-get install -y nfs-kernel-server
	cat - << EOS | sudo sh -c "cat - > /etc/exports"
# /etc/exports: the access control list for filesystems which may be exported
#		to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/nfsroot/ ${hostif_netw_mask}(rw,sync,no_root_squash,no_subtree_check)
EOS
	sudo mkdir -p /nfsroot
	sudo exportfs -ra
	sudo exportfs -v

	portfix_nfs
	## verify/postcondition check
}

portfix_nfs() {
	## guard/precondition check

	## install/setup
	sudo sed --in-place -e 's/^STATDOPTS=/STATDOPTS="--port 32765 --outgoing-port 32766"/' /etc/default/nfs-common
	sudo sed --in-place -e "s/^RPCMOUNTDOPTS=\"\(.*\)\"/RPCMOUNTDOPTS=\"\1 -p 32767\"/" /etc/default/nfs-kernel-server
	cat - <<EOS | sudo sh -c "cat - > /etc/modprobe.d/local.conf"
options lockd nlm_udpport=32768 nlm_tcpport=32768
options nfs callback_tcpport=32764
EOS

	sudo ufw allow proto tcp from ${hostif_netw_mask} to any port 111,2049,32765,32767,32768
	sudo ufw allow proto udp from ${hostif_netw_mask} to any port 111,2049,32765,32767,32768

	echo "reboot required: NFS server config updated"
}

update_ufw() {
	sudo sed --in-place -e 's/DEFAULT_FORWARD_POLICY=".*"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw

	sudo sed --in-place -e 's/^#net\/ipv4\/ip_forward=1/net\/ipv4\/ip_forward=1/' /etc/ufw/sysctl.conf

	cat - << EOS | sudo sh -c "cat - >> /etc/ufw/before.rules"

*nat
-F
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s ${hostif_netw_mask} -o eth0 -j MASQUERADE
COMMIT
EOS

	sudo ufw allow ssh
	sudo ufw allow tftp
	sudo ufw disable
	sudo ufw --force enable
}

install_dnsmasq() {
	sudo apt-get -y install dnsmasq
	sudo systemctl stop dnsmasq
	cat - << EOS | sudo sh -c "cat - >> /etc/dnsmasq.conf"
listen-address=${hostif_addr}
interface=${hostif_name}
bind-interfaces
EOS
	sudo ufw allow 53/udp
	sudo ufw allow 53/tcp
	sudo systemctl start dnsmasq
}

install_dhcpd() {
	local dhcp_range="192.168.1.16 192.168.1.64"
	sudo apt-get -y install isc-dhcp-server
	sudo sed --in-place \
		-e 's/^#DHCPDv4_CONF=/DHCPDv4_CONF=/' \
		-e 's/^#DHCPDv4_PID=/DHCPDv4_PID=/' \
		-e 's/INTERFACESv4=""/INTERFACESv4="'${hostif_name}'"/' \
		/etc/default/isc-dhcp-server
	cat - << EOS | sudo sh -c "cat - >> /etc/dhcp/dhcpd.conf"
subnet ${hostif_netw} netmask ${hostif_mask} {
	option routers ${hostif_addr};
	option domain-name-servers ${hostif_addr};
	range ${dhcp_range};
}
EOS
	sudo systemctl enable isc-dhcp-server
	sudo systemctl restart isc-dhcp-server
}

install_apt_cache() {
	sudo apt-get -y install apt-cacher-ng
	sudo ufw allow 3142/tcp
	cat - << EOS > 02_apt_cached_proxy.sample
##place me at /etc/apt/apt.conf.d/
Acquire::http::Proxy "http://${hostif_addr}:3142/";
EOS
}

install_docker() {
	sudo apt-get -y remove docker docker-engine docker.io containerd runc
	sudo apt-get update
	sudo apt-get -y install \
		apt-transport-https ca-certificates curl \
		gnupg-agent software-properties-common
	curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
	sudo add-apt-repository \
		"deb [arch=arm64] https://download.docker.com/linux/ubuntu \
		$(lsb_release -cs) \
		stable"
	sudo apt-get update
	sudo apt-get -y install docker-ce docker-ce-cli containerd.io
	sudo docker run hello-world
	sudo gpasswd -a ${USER} docker
	echo "Reboot or Login again; ${USER} has been added to group docker"
}

install_samba() {
	sudo apt-get -y install samba
	(echo ${samba_passwd}; echo ${samba_passwd}) | sudo smbpasswd -s -a ${USER}
	cat - << EOS | sudo sh -c "cat - >> /etc/samba/smb.conf"
[homes]
   comment = Home Directories
   browseable = yes
   read only = no
#   create mask = 0700
#   directory mask = 0700
   valid users = %S
EOS
	sudo systemctl reload smbd
	sudo systemctl restart smbd
	sudo ufw allow samba
}

#### run
install_tools
adjust_time
install_tftp
address_usb_ether
install_nfs
update_ufw
install_dnsmasq
install_dhcpd
install_apt_cache
install_docker
install_samba
