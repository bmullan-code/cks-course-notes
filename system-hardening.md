## System Hardening

|      |      |      |
| ---- | ---- | ---- |
|Minimize Host OS Footprint | Limit Node Access | SSH Hardening | 
|Privilidge escalation in linux | Remove obsolete packages and services | Restrict Kernel Modules| 
|Identify and disable open ports | minimize iam roles | UFW Firewall Baiscs | Restricting syscals using secomp |
|seccomp in kubernetes | kernel hardening tools - app armor | 

### Least Prvilige Principle

eg.
- limit access to nodes
- rbac access
- remove obsolete packages
- restrict network access
- restrict obsolete kernel modules
- identify and fix open ports

### Minimize host os footprint

### Reducing the attack surface

#### Limit Access to the nodes
- provision control plane nodes in a private network
- authorized networks based on source ip address range
- accounts
- - user, root, system and service accounts
```
# some commands
id 
who
last
```
- Access control files
```
# password file
/etc/passwd
# actual passwords
/etc/shadow
# groups
/etc/group
```
- remove or disabble any account that has no use in the system
```
usermod -s /bin/nologin michael
# or 
userdel michael
```
- remove users from group that they should not belong
```
id michael
deluser michael admin
id michael
```
- Creating a user with options
```
# useradd -m -d /opt/sam -u 2328 -g admin -s /bin/bash sam 
root@controlplane:~# id sam
uid=2328(sam) gid=1000(admin) groups=1000(admin)
```

### SSH Hardening

### Privilidge escalation in linux

- root access may be disabled in ssh
```
/etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no
```
- can use sudo for escalation
```
/etc/sudoers
```
- you can disable login by root be setting the /usr/sbin/nologin
- /etc/sudoers file has the following format
1. user or group (groups begin with %)
2. hosts (default ALL)
3. user (ALL default)
4. command (eg. /bin/ls, /usr/bin/shutdown

- creating an ssh user on another node
```
# ssh into node01 host from controlplane host
ssh node01

# Create user jim on node01 host
adduser jim (set any password you like)

# Return back to controlplane host and copy ssh public key
ssh-copy-id -i ~/.ssh/id_rsa.pub jim@node01

# Test ssh access from controlplane host
ssh jim@node01
```
- add a user with group
```
useradd -g admin rob
```
- set ssh password options
```
# On node01 host open /etc/ssh/sshd_config config file using any editor like vi and make appropriate changes
Change: PermitRootLogin yes
To: PermitRootLogin no

Change: #PasswordAuthentication yes
To: PasswordAuthentication no

Restart sshd service
service sshd restart
```

### Remove Obsolete Packages
- install only the required packages
- remove unwanted services
```
systemctl list-units --type service
systemctl status apache2
systemctl stop apache2
systemctl disable apache2
apt remove apache2
```

### Restrict Kernel Modules
- to list all modules
```
lsmod
# to install a module
modprobe pcspkr

```
- blacklist a kernel module will prevent it from loading
```
cat /etc/modprobe.d/blacklist.conf
blacklist sctp
blacklist dccp

# to test
shutdown -r now
lsmod | grep dccp
```
- refer to 3.4 in the cis benchmark - uncommon network protocols

### Identify and disable open ports
- to check for open listen ports
```
netstat -an | grep -w LISTEN
```
- to identify what services ports are used for 
```
cat /etc/services | grep -w 53

domain 53/tcp # Domain name server
domain 53/udp

# also (shows service name)
netstat -natp | grep 9090

```
- make use of the reference documentation to know which ports should be open, for example for k8s control plane, k8s worker node etc.

#### Lab
- Which of the following commands is used to list all installed packages on an ubuntu system?
```
# apt list --installed
Listing... Done
adduser/bionic,now 3.116ubuntu1 all [installed]
apache2/bionic-updates,bionic-security,now 2.4.29-1ubuntu4.16 amd64 [installed]
apache2-bin/bionic-updates,bionic-security,now 2.4.29-1ubuntu4.16 amd64 [installed,automatic]
apache2-data/bionic-updates,bionic-security,now 2.4.29-1ubuntu4.16 all [installed,automatic]
apache2-utils/bionic-updates,bionic-security,now 2.4.29-1ubuntu4.16 amd64 [installed,automatic]
apparmor/bionic-updates,bionic-security,now 2.12-4ubuntu5.1 amd64 [installed,automatic]
....
```
- List Active Services
```
root@controlplane:~# systemctl list-units --type service
UNIT                               LOAD   ACTIVE SUB     DESCRIPTION                                
apparmor.service                   loaded active exited  AppArmor initialization                    
containerd.service                 loaded active running containerd container runtime               
dbus.service                       loaded active running D-Bus System Message Bus                   
docker.service                     loaded active running Docker Application Container Engine   
```
- Which command can be used to list the kernel modules currently loaded on a system?
```
root@controlplane:~# lsmod
Module                  Size  Used by
ip6table_mangle        16384  1
nfsd                  393216  0
auth_rpcgss            94208  1 nfsd
nfs_acl                16384  1 nfsd
lockd                  98304  1 nfsd
grace                  16384  2 nfsd,lockd
```
- Stop the nginx service and remove its service unit file.
```
root@controlplane:~# systemctl stop nginx
root@controlplane:~# systemctl disable nginx
Synchronizing state of nginx.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install disable nginx
root@controlplane:~# systemctl list-units --all | grep nginx
root@controlplane:~# systemctl status nginx
● nginx.service - A high performance web server and a reverse proxy server
   Loaded: loaded (/lib/systemd/system/nginx.service; disabled; vendor preset: enabled)
   Active: inactive (dead)
     Docs: man:nginx(8)
root@controlplane:~# rm /lib/systemd/system/nginx.service
```
- We have a service running on controlplane host which is listening on port 9090. Identify the service and kill the same to free the 9090 port.
```
root@controlplane:~# netstat -natp | grep 9090
tcp        0      0 0.0.0.0:9090            0.0.0.0:*               LISTEN      16496/apache2  

root@controlplane:~# systemctl stop apache2
```
- We have the wget package version v1.18 installed on the host controlplane. Check for updates available for this package and update to the latest version available in the apt repos
```
root@controlplane:~# apt show wget -a
Package: wget
Version: 1.19.4-1ubuntu2.2
Priority: standard
Section: web
...

Package: wget
Version: 1.19.4-1ubuntu2
Priority: standard
Section: web
...

Package: wget
Version: 1.18-5+deb9u3
Status: install ok installed
Priority: important
Section: web

apt upgrade wget
Reading package lists... Done
Building dependency tree       
...

Setting up wget (1.19.4-1ubuntu2.2) ...
Setting up curl (7.58.0-2ubuntu3.14) ...
Processing triggers for dbus (1.12.2-1ubuntu1.2) ...
Processing triggers for libc-bin (2.27-3ubuntu1.4) ...
root@controlplane:~# 
```





