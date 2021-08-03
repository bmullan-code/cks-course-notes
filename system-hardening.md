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




