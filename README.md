
## Cluster Setup & Hardening 
### CIS benchmarks 
### Authentication & Authorization mechanisms 
### Service Accounts 
### TLS 
### Node Metadata
### K8S Dashboard and securing it
### Platform Binaries
### Upgrade k8s
### Network policy 
### Secure ingress 


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

### Security Primitives

* kube-apiserver
* who can access and what can they do. 
* authenticate - usernames/password, certificate, external eg. ldap, service accounts
* authorization - rbac, groups and user permissions, abac etc.

Components (all secured by tls certs)
* Kube API Server
* ETCD
* Kubelet
* Kube Proxy
* Kube Scheduler
* Kube Controller Manager

By default all components can talk to each other, you can control comms by network policies.

### Authentication

- multiple nodes
- access by admin, developers, end users, 3rd party application for integration.
- focus is on admin users
- - users (human) 
- - robots
- k8s does not manage regular users
- k8s does manage service accounts

#### Users 
- all requests go through kube-apiserver, authenticates first and then processes
- users
- - static password file
- - static token file
- - certificates
- - identity services (ldap, kerberos etc.)

#### User File Authentication.
```
user-details.csv
password, user, id, group(optional)

kube-apiserver -basic-auth-file=user-details.csv
```

If using kubeadm
```
/etc/kubernetes/manifests/kube-apiserver.yaml

spec:
  containers:
  - command:
  - kube-apiserver
  ...
  - --basic-auth-file=user-details.csv
 ```
 
 you can then pass user/pass in a curl cmd eg.
 ```
 curl -v -k https://master-node-ip:6443/api/v1/pods -u "user1:pass"
 ```
 
 #### Token File Authentication
 ```
 user-token-details.csv
 kjjsskkkksi,user10,u0001,group1
 
 kube-apiserver --token-auth-file=user-token-details.csv
 
 curl -v -k https://master-node-ip:6443/api/v1/pods --header "Authorization: Bearer  kjjsskkkksi"
 ```
 
Note! : These two methods are considered insecure. 


### Service Accounts

User Accounts (humans)
Service Accounts (machines)

```
kubectl create serviceaccount dashboard-sa

kubectl get sa

```
Token is created automatically as a secrete using the name format
```
sa-name-token-<unique>
```

To view token
```
kubectl describe secret sa-name-token-unique
```
This token can then be used as a bearer token to the k8s api.
```
curl  -v -k https://master-node-ip:6443/api --header "Authorization: Bearer eyjhb...."
```

- A default service account is created automatically in every namespace
- A pod in that namespace automatically mounts that service account token secret
- /var/run/secretes/kubernetes.io/serviceaccount
- You can see this by running an ls on that location eg.
```
kubectl exec -it my-kubernetes-dashboard ls /var/run/secretes/kubernetes.io/serviceaccount
ca.crt namespace token
```
- token is in the file "token"
- default service account is restricted to running queries. 
- to use a account service account specify it in the pod
```
spec:
  containers:
  serviceAccount : dashboard-sa
```

### Service Account rbac
```
cat /var/rbac/dashboard-sa-role-binding.yaml 
---
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: ServiceAccount
  name: dashboard-sa # Name is case sensitive
  namespace: default
roleRef:
  kind: Role #this must be Role or ClusterRole
  name: pod-reader # this must match the name of the Role or ClusterRole you wish to bind to
  apiGroup: rbac.authorization.k8s.io

$ cat /var/rbac/pod-reader-role.yaml 
---
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups:
  - ''
  resources:
  - pods
  verbs:
  - get
  - watch
  - list
```

Get the sa secret and token
```
k get secret
NAME                       TYPE                                  DATA   AGE
dashboard-sa-token-6jxkt   kubernetes.io/service-account-token   3      3m8s
default-token-jqwxm        kubernetes.io/service-account-token   3      177m
controlplane $ k describe secret dashboard-sa-token-6jxkt
Name:         dashboard-sa-token-6jxkt
Namespace:    default
Labels:       <none>
Annotations:  kubernetes.io/service-account.name: dashboard-sa
              kubernetes.io/service-account.uid: 4ad0ff43-6acf-44cf-9ce9-1f2225a444a5

Type:  kubernetes.io/service-account-token

Data
====
ca.crt:     1066 bytes
namespace:  7 bytes
token:      eyJhbGciOiJSUzI1NiIsImtpZCI6InVRamk0bGhqbzZsVGFFa21yU0FkZndCVWNoc1VqSHU4VFlfNmFZakRjbmcifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRhc2hib2FyZC1zYS10b2tlbi02anhrdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJkYXNoYm9hcmQtc2EiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiI0YWQwZmY0My02YWNmLTQ0Y2YtOWNlOS0xZjIyMjVhNDQ0YTUiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDpkYXNoYm9hcmQtc2EifQ.G1kZGXm8lp1YIlk_S0qgbgU6AaZCxiSq8QwF8UctixTfNt_XuYvsI_bYcMRu3glJKwMtE4YrEIlFMuk6SCjc45LkczzNvWTmPc05SlIukxTl5KPOcg2A-Ps-z58evcijUu-maoBu38v0AJSjsQNL4liionYZIFpkcy_KheoafXiERDJgHDvJmQNyIHpeWmQptIFWh13hXz1g-zavHdB0dy_Vn-QfuxzRvFwlasDgAK1-l00G61FD3qCYRBfqTr7qtRnoDQIqogBk7k4rzwOW0kOQgWUbNsxxMcyRfT3fFi9yIswOT0rJLsj__HjgLgXpF8mCyFgnCvM1IiS8zJqXDA
```



  






 




 
