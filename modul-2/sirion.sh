auto eth0
iface eth0 inet static
    address 10.89.3.10
    netmask 255.255.255.0
    gateway 10.89.3.1
    up echo nameserver 192.168.122.1 > /etc/resolv.conf