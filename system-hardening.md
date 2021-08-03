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


