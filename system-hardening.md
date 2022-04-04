## System Hardening

|      |      |      |
| ---- | ---- | ---- |
|Minimize Host OS Footprint | Limit Node Access | SSH Hardening | 
|Privilege escalation in linux | Remove obsolete packages and services | Restrict Kernel Modules| 
|Identify and disable open ports | minimize iam roles | UFW Firewall Baiscs | Restricting syscals using secomp |
|seccomp in kubernetes | kernel hardening tools - app armor | 

### Least Privilege Principle

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

### Privilege escalation in linux

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

### Minimize IAM Roles

- particularly in the public cloud its not a good idea to use admin/root users
- with root account a user can create/manage any service in the cloud
- use the root account to create other users and assign permissions
- An iam group is a collection of users, we can assign permissions to a group
- AWS : Use AWS Trusted Advisor
- GCP : Security Command Center
- Azure : Azure Advisor

### Minimize External Access

- firewall appliances
- ufw firewall on servers

#### UFW (uncomplicated firewall)

- iptables (learning curve)
- ufw is easier, frontend for iptables
- find ports that are listtening for connections
```
netstat -an | grep -w LISTEN
```
- install and setup ufw
```
apt-get update
apt-get install ufw
systemctl enable ufw
systemctl start ufw
# to see status
ufw status
# add some rules

# allow all outgoing
ufw default allow outgoing

# deny all inbound
ufw default deny incoming

# allow ssh from a specific ip
ufw allow from 172.16.238.5 to any port 22 proto tcp

# allow htttp from a specific ip
ufw allow from 172.16.238.5 to any port 80 proto tcp

# allow from an ip range
ufw allow from 172.16.100.5/28 to any port 80 proto tcp

# deny to a specific port
ufw deny 8080

# to enable the firewall
ufw enable

# to check status 
ufw status

# to delete a rule
ufw delete deny 8080

# or delete by line number
ufw delete 5

# use to show rule numbers
ufw status numbered

# ufw to allow a port range
ufw allow starting\_port:ending_port/protocol
eg.
ufw allow 1000:2000/tcp

# reset all rules
ufw reset

# Examples
ufw allow from 135.22.65.0/24 to any port 9090 proto tcp
ufw allow from 135.22.65.0/24 to any port 9091 proto tcp


# find a port a specific service is running on 
# netstat -antp | grep lighttpd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      9269/lighttpd  

```

### Linux Syscalls

- linux kernel is the core interface between hardware and processes
- kernel space : kernel runs in kernel space (kernel, device drivers etc.)
- user space : apps run in user space
- apps running in user space make system calls to access devices etc.

#### Tracing System calls

- which strace
```
/usr/bin/strace
```
- eg/ strace touch /tmp/error.log
```
ubuntu@opsmanager-2-10:~$ strace touch /tmp/error.log
execve("/usr/bin/touch", ["touch", "/tmp/error.log"], [/* 15 vars */]) = 0
brk(NULL)                               = 0x1b0f000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=30960, ...}) = 0
```
- to get the pid of a process use the pidof command
```
pidof etcd
3596
```
- then we can strace the process for all future syscalls
```
pidof -p 3596
```

### Aquasec Tracee

- traces syscalls in containers
- uses ebpf
- eg.
```
docker run --name tracee --rm --privileged --pid=host \ 
  -v /lib/modules/:/lib/modules/:ro   \
  -v /usr/src:/usr/src:ro \
  -v /tmp/tracee:/tmp/tracee   \
  aquasec/tracee:0.4.0 --trace comm=ls  
```

- to trace syscalls from a new container
```
docker run --name tracee --rm --privileged --pid=host \ 
  -v /lib/modules/:/lib/modules/:ro   \
  -v /usr/src:/usr/src:ro \
  -v /tmp/tracee:/tmp/tracee   \
  aquasec/tracee:0.4.0 --trace container=new
```

### Restricting syscalls

- by default the kernel will allow any syscall from a process in user space
-  use seccomp to restrict syscalls
-  to check for seccomp enabled
```
grep -i seccomp /boot/config-$(uname -r)
CONFIG_HAVE_ARCH_SECCOMP_FILTER=y
CONFIG_SECCOMP_FILTER=y
CONFIG_SECCOMP=y
```
- example to test it
```
docker run docker/whalesay cowsay hello
```
- Seccomp operates in 3 modes
- - mode 0 - disabled
- - mode 1 - strict
- - mode 2 - filtered
- eg.
```
 docker run -it --rm docker/whalesay /bin/sh
# ps -ef
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 23:50 pts/0    00:00:00 /bin/sh
root           7       1  0 23:50 pts/0    00:00:00 ps -ef
# grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
- docker has a built in seccomp filter. 
- limits to about 60 out of 300 syscalls
- you can use the following to specify a custom seccomp profile
```
docker run -it --rm --security-opt seccomp=/root/custom.json docker/whalesay /bin/sh
```
- you can disable seccomp with 
```
docker run -it --rm --security-opt seccomp=unconfined docker/whalesay /bin/sh
```

### implement seccomp in kubernetes

- to test what syscalls are blocked we can run this container
```
docker run r.j3ss.co/amicontained amicontained
```
- to run in kubernetes
```
kubectl run amicontained --image r.j3ss.co/amicontained amicontained -- amicontained
kubectl logs amicontained
```
- to apply a seccomp profile
```
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: amicontained
  name: amicontained
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - args:
    - amicontained
    image: r.j3ss.co/amicontained
    name: amicontained
    securityContext:
      allowPrivilegeEscalation: false
      

PS G:\tkgi> k logs amicontained
Container Runtime: kube
Has Namespaces:
        pid: true
        user: false
AppArmor Profile: docker-default (enforce)
Capabilities:
        BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap
Seccomp: filtering
Blocked Syscalls (60):
        SYSLOG SETPGID SETSID USELIB USTAT SYSFS VHANGUP PIVOT_ROOT _SYSCTL ACCT SETTIMEOFDAY MOUNT UMOUNT2 SWAPON SWAPOFF REBOOT SETHOSTNAME SETDOMAINNAME IOPL IOPERM CREATE_MODULE INIT_MODULE DELETE_MODULE GET_KERNEL_SYMS QUERY_MODULE QUOTACTL NFSSERVCTL GETPMSG PUTPMSG AFS_SYSCALL TUXCALL SECURITY LOOKUP_DCOOKIE CLOCK_SETTIME VSERVER MBIND SET_MEMPOLICY GET_MEMPOLICY KEXEC_LOAD ADD_KEY REQUEST_KEY KEYCTL MIGRATE_PAGES UNSHARE MOVE_PAGES PERF_EVENT_OPEN FANOTIFY_INIT NAME_TO_HANDLE_AT OPEN_BY_HANDLE_AT SETNS PROCESS_VM_READV PROCESS_VM_WRITEV KCMP FINIT_MODULE KEXEC_FILE_LOAD BPF USERFAULTFD PKEY_MPROTECT PKEY_ALLOC PKEY_FREE
Looking for Docker.sock
PS G:\tkgi>
```

- you can also specify local json files
```
mkdir -p /var/lib/kubelet/seccomp/profiles

/var/lib/kubelet/seccomp/profiles/audit.json
{
   'defaultAction' : 'SCPM_ACT_LOG'
}


apiVersion: v1
kind: Pod
metadata:
  name: test-audit
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localHostProfile: profiles/audit.json
  containers:
  - command: ["bash","-c","echo 'i just made a syscall' && sleep 100"]
    image: ubuntu
    name: ubuntu
    securityContext:
      allowPrivilegeEscalation: false

logs in 
grep syscall /var/log/syslog

# map numbers to syscall names


```

#### Sample Tracee output
```
controlplane $ ssh node01
src:/usr/src:ro -v /tmp/tracee:/tmp/tracee -it aquasec/tracee:0.4.0 --trace container=newro -v /usr/s
Unable to find image 'aquasec/tracee:0.4.0' locally
0.4.0: Pulling from aquasec/tracee
596ba82af5aa: Pull complete 
79838d9f31c1: Pull complete 
1ecb0bc0816d: Pull complete 
8006fb4fbef7: Pull complete 
Digest: sha256:d2706ee950677763991fb434b228f78cb8a05c20a85e537e131181cc0fe85fe3
Status: Downloaded newer image for aquasec/tracee:0.4.0
TIME(s)        UTS_NAME         UID    COMM             PID/host        TID/host        RET              EVENT                ARGS
534.293947     hello            0      runc:[2:INIT]    1      /14450   1      /14450   0                execve               pathname: /pause, argv: [/pause]
534.294016     hello            0      runc:[2:INIT]    1      /14450   1      /14450   0                security_bprm_check  pathname: /pause, dev: 265289728, inode: 3158150
535.519725     hello            0      runc:[2:INIT]    1      /14582   1      /14582   0                execve               pathname: /usr/bin/echo, argv: [echo hello]
535.519812     hello            0      runc:[2:INIT]    1      /14582   1      /14582   0                security_bprm_check  pathname: /usr/bin/echo, dev: 265289728, inode: 5517430
535.519865     hello            0      runc:[2:INIT]    1      /14582   1      /14582   0                cap_capable          cap: CAP_SYS_ADMIN
535.519872     hello            0      runc:[2:INIT]    1      /14582   1      /14582   0                cap_capable          cap: CAP_SYS_ADMIN
535.519885     hello            0      runc:[2:INIT]    1      /14582   1      /14582   0                cap_capable          cap: CAP_SYS_ADMIN
535.519889     hello            0      runc:[2:INIT]    1      /14582   1      /14582   0                cap_capable          cap: CAP_SYS_ADMIN
535.519894     hello            0      runc:[2:INIT]    1      /14582   1      /14582   0                cap_capable          cap: CAP_SYS_ADMIN
535.519898     hello            0      runc:[2:INIT]    1      /14582   1      /14582   0                cap_capable          cap: CAP_SYS_ADMIN
535.520654     hello            0      echo             1      /14582   1      /14582   -2               access               pathname: /etc/ld.so.preload, mode: R_OK
535.520689     hello            0      echo             1      /14582   1      /14582   0                security_file_open   pathname: /etc/ld.so.cache, flags: O_RDONLY|O_LARGEFILE, dev: 265289728, inode: 5517223
535.520747     hello            0      echo             1      /14582   1      /14582   3                openat               dirfd: -100, pathname: /etc/ld.so.cache, flags: O_RDONLY|O_CLOEXEC, mode: 0
535.520764     hello            0      echo             1      /14582   1      /14582   0                fstat                fd: 3, statbuf: 0x7FFC77256FB0
535.520786     hello            0      echo             1      /14582   1      /14582   0                close                fd: 3
535.520812     hello            0      echo             1      /14582   1      /14582   0                security_file_open   pathname: /usr/lib/x86_64-linux-gnu/libc-2.31.so, flags: O_RDONLY|O_LARGEFILE, dev: 265289728, inode: 5518083
535.520844     hello            0      echo             1      /14582   1      /14582   3                openat               dirfd: -100, pathname: /lib/x86_64-linux-gnu/libc.so.6, flags: O_RDONLY|O_CLOEXEC, mode: 0
535.520878     hello            0      echo             1      /14582   1      /14582   0                fstat                fd: 3, statbuf: 0x7FFC77257000
535.520988     hello            0      echo             1      /14582   1      /14582   0                close                fd: 3
535.521266     hello            0      echo             1      /14582   1      /14582   0                fstat                fd: 1, statbuf: 0x7FFC77257BD0
535.521296     hello            0      echo             1      /14582   1      /14582   0                close                fd: 1
535.521305     hello            0      echo             1      /14582   1      /14582   0                close                fd: 2
535.521386     hello            0      echo             1      /14582   1      /14582   0                sched_process_exit   
535.754993     hello            0      pause            1      /14450   1      /14450   0                sched_process_exit   


```
- example of applying a profile
```
controlplane $ cat /var/lib/kubelet/seccomp/profiles/audit.json 
{
    "defaultAction": "SCMP_ACT_LOG"
}
controlplane $ 

cat /var/answers/audit-nginx.yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: nginx
  name: audit-nginx
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/audit.json
  containers:
  - image: nginx
    name: nginx
controlplane $ k apply -f /var/answers/audit-nginx.yaml

```

### AppArmor

- fine grained control over the processes running in a container
- to check if it is running
```
ubuntu@opsmanager-2-10:~$ systemctl status apparmor
 apparmor.service - LSB: AppArmor initialization
   Loaded: loaded (/etc/init.d/apparmor; bad; vendor preset: enabled)
   Active: active (exited) since Tue 2021-08-10 19:33:14 UTC; 1 day 5h ago
     Docs: man:systemd-sysv-generator(8)
    Tasks: 0
   Memory: 0B
      CPU: 0```
```
- apparmor needs to be enabled on each of the nodes in the cluster
```
cat /sys/module/apparmor/parameters/enabled
Y
```
- to look at the apparmor profiles
```
ubuntu@opsmanager-2-10:~$ cat /sys/kernel/security/apparmor/profiles
cat: /sys/kernel/security/apparmor/profiles: Permission denied
ubuntu@opsmanager-2-10:~$ sudo cat /sys/kernel/security/apparmor/profiles
/usr/sbin/tcpdump (enforce)
/usr/sbin/ntpd (enforce)
/usr/lib/connman/scripts/dhclient-script (enforce)
/usr/lib/NetworkManager/nm-dhcp-helper (enforce)
/usr/lib/NetworkManager/nm-dhcp-client.action (enforce)
/sbin/dhclient (enforce)
```
- example of a profile
```
profile apparmor-deny-write flags=(attach_disconnected) {
   file,
   # deny all file writes
   deny /** w/,
}
```
- to check status of apparmor
```
aa-status

ubuntu@opsmanager-2-10:~$ sudo aa-status
apparmor module is loaded.
6 profiles are loaded.
6 profiles are in enforce mode.
   /sbin/dhclient
   /usr/lib/NetworkManager/nm-dhcp-client.action
   /usr/lib/NetworkManager/nm-dhcp-helper
   /usr/lib/connman/scripts/dhclient-script
   /usr/sbin/ntpd
   /usr/sbin/tcpdump
0 profiles are in complain mode.
1 processes have profiles defined.
1 processes are in enforce mode.
   /usr/sbin/ntpd (942)
0 processes are in complain mode.
0 processes are unconfined but have a profile defined.
```
- modes can be enforce, complain, unconfined


### Creating AppArmor Profiles

- apparmor utils
```
apt-get install -y apparmor-utils

aa-genproof /root/add_data.sh

# profile is created in 
/etc/apparmor.d/root.add_data.sh
```

### running apparmor in kubernetes
- apparmor kernel required on all nodes
- apparmor profile on each node
- eg.
```
pod does not need to write to fs, make sure profile (see example below) is on each node

apiVersion: v1
kind: Pod
metadata:
  name: my-pod
  annotations:
    container.apparmor.security.beta.kubernetes.io/<container-name>: localhost/profile-name
  ...
  
# test writing to fs
kubectl exec -ti my-pod -- touch /tmp/test
... permission denied error
```
- to load a profile
```
apparmor_parser -q /etc/apparmor.d/usr.sbin.nginx
```

#### AppArmor from Mock Exam 1

```
# apparmor profile provided in  /etc/apparmor.d/frontend
ssh node01
# apparmor status
systemctl status apparmor
# enabled ?
cat /sys/module/apparmor/parameters/enabled
# profiles
cat /sys/kernel/security/apparmor/profiles
# status
aa-status
# check the provided profile
cat /etc/apparmor.d/frontend
# check to see if profile is loaded
aa-status | grep frontend
cat /sys/kernel/security/apparmor/profiles | grep frontend
# load the profile
apparmor_parser -r /etc/apparmor.d/frontend
# check that it was loaded
root@node01:~# cat /sys/kernel/security/apparmor/profiles | grep frontend
restricted-frontend (enforce)

# apply the profile to the pod via annotation
metadata:
  name: frontend-site
  annotations:
    container.apparmor.security.beta.kubernetes.io/nginx: localhost/restricted-frontend

```

### Linux Capabilities
- how to add or drop linux capabilities on pods
- eg. bby default a pod cannot change the date
- examples of capabilities (there are dozens)
- - CAP_CHOWN, CAP_SYS_TIME
- to check for capability
```
ubuntu@opsmanager-2-10:~$ getcap /usr/bin/ping
```
- A container even wheen run as root only has a limited set of capabilities
- capabilities can be added or removed for a container with 
```
...
spec:
  containers:
  ...
  securityContext:
    capabilities:
      add: ["SYS_TIME"]
      drop: ["CHOWN"]
```
