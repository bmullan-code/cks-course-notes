
# Cluster Setup & Hardening 
## CIS benchmarks 
## Authentication & Authorization mechanisms 
## Service Accounts 
## TLS 
## Node Metadata
## K8S Dashboard and securing it
## Platform Binaries
## Upgrade k8s
## Network policy 
## Secure ingress 


### CIS Benchmarks 

* Security benchmark. For example, get to data server and infect via a usb device (physical access), so usb ports should be disable by default. 
* Access – who can access, and who can access as root. Sudo is configured and only certain users 
* Network – firewall rules, only allow certain port.  
* Services – only necessary services eg. Ntp, all others disabled.  
* Filesystem permissions – disable unneeded file system 
* Many more best practies.  
* CIS benchmarks allows us to assess our servers against these best practies.  
* Center for Inernet Security (CIS) 

* run assessment report
```
sh ./Assessor-CLI.sh -i -rd /var/www/html/ -nts -rp index
```


 
