
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

sh ./Assessor-CLI.sh -i -rd /var/www/html/ -nts -rp index
Use below setting while running tests

Benchmarks/Data-Stream Collections: : CIS Ubuntu Linux 18.04 LTS Benchmark v2.0.1

Profile : Level 1 - Server

```

* CIS for kubernetes
* Download from CIS Web Site
* https://workbench.cisecurity.org/
* kube-bench from Aqua Security
* Deploy as a docker container, or a pod or a binary.
* Download and install.
```
curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.4.0/kube-bench_0.4.0_linux_amd64.tar.gz -o kube-bench_0.4.0_linux_amd64.tar.gz
tar -xvf kube-bench_0.4.0_linux_amd64.tar.gz
```
run kube-bench
```
./kube-bench --config-dir `pwd`/cfg --config `pwd`/cfg/config.yaml 
```


 
