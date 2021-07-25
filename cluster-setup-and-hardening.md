
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


- Specify the service account in a deployment yaml eg.
```
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: my-deployment
spec:
  template:
    # Below is the podSpec.
    metadata:
      name: ...
    spec:
      serviceAccountName: build-robot
      automountServiceAccountToken: false
```


### TLS Certificate Basics

- certificates establish trust between parties.
- symmetric .v. asymetric encryption
- key pair - private key, public key. 
- Certificate Authorities


#### View Certificate Details
- healthcheck of certificates.
- "the hard way" .v. kubeadm
- thw = /etc/systemd/kube-apiserver.service
- kubeadm = /etc/kubernetes/manifests/kube-apiserver.yaml

##### Lab
- kube-api server cert file.
```
# cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep crt
    - --client-ca-file=/etc/kubernetes/pki/ca.crt
    - --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt
    - --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt
    - --kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt
    - --proxy-client-cert-file=/etc/kubernetes/pki/front-proxy-client.crt
    - --requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt
    - --tls-cert-file=/etc/kubernetes/pki/apiserver.crt
    
    /etc/kubernetes/pki/apiserver.crt
    
```
- Identify the Certificate file used to authenticate kube-apiserver as a client to ETCD Server
```
# cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep etcd
    - --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt
    - --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt
    - --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key
    - --etcd-servers=https://127.0.0.1:2379
    
    /etc/kubernetes/pki/apiserver-etcd-client.crt
```
- Identify the key used to authenticate kubeapi-server to the kubelet server
```
# cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep kubelet
    - --kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt
    - --kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key
    - --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname
    
    /etc/kubernetes/pki/apiserver-kubelet-client.key
```
- Identify the ETCD Server Certificate used to host ETCD server
```
# cat /etc/kubernetes/manifests/etcd.yaml | grep crt
    - --cert-file=/etc/kubernetes/pki/etcd/server.crt
    - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt
    - --peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
    - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
    
    /etc/kubernetes/pki/etcd/server.crt
```
- Identify the ETCD Server CA Root Certificate used to serve ETCD Server
```
/etc/kubernetes/pki/etcd/ca.crt
```
- What is the Common Name (CN) configured on the Kube API Server Certificate?
```
# openssl x509 -in /etc/kubernetes/pki/apiserver.crt -text -noout | grep CN
        Issuer: CN = kubernetes
        Subject: CN = kube-apiserver
        
        kube-apiserver
```
- What is the name of the CA who issued the Kube API Server Certificate?
```
# openssl x509 -in /etc/kubernetes/pki/apiserver.crt -text -noout | grep Issuer
        Issuer: CN = kubernetes
```
- Which of the below alternate names is not configured on the Kube API Server Certificate?
```
# openssl x509 -in /etc/kubernetes/pki/apiserver.crt -text -noout | grep -A 1 Alternative
            X509v3 Subject Alternative Name: 
                DNS:controlplane, DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster.local, IP Address:10.96.0.1, IP Address:10.22.248.6

```
- What is the Common Name (CN) configured on the ETCD Server certificate?
```
# openssl x509 -in /etc/kubernetes/pki/etcd/server.crt -noout -text | grep CN
        Issuer: CN = etcd-ca
        Subject: CN = controlplane
        
        controlplane
```
- How long, from the issued date, is the Kube-API Server Certificate valid for?
```
# openssl x509 -in /etc/kubernetes/pki/apiserver.crt -text -noout | grep -A 3 Validity
        Validity
            Not Before: Jul 24 15:52:33 2021 GMT
            Not After : Jul 24 15:52:34 2022 GMT
        Subject: CN = kube-apiserver
        
        1 year
```
- How long, from the issued date, is the Root CA Certificate valid for?
```
openssl x509 -in /etc/kubernetes/pki/ca.crt -text -noout | grep -A 3 Validity
        Validity
            Not Before: Jul 24 15:52:33 2021 GMT
            Not After : Jul 22 15:52:33 2031 GMT
        Subject: CN = kubernetes
        
        10 years
```
- Kubectl suddenly stops responding to your commands. Check it out! Someone recently modified the /etc/kubernetes/manifests/etcd.yaml file
```
cat /etc/kubernetes/manifests/etcd.yaml | grep crt
    - --cert-file=/etc/kubernetes/pki/etcd/server-certificate.crt
    - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt
    - --peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
    - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
root@controlplane:~# ls /etc/kubernetes/pki/etcd/server-certificate.crt
ls: cannot access '/etc/kubernetes/pki/etcd/server-certificate.crt': No such file or directory
```

- The kube-api server stopped again! Check it out. Inspect the kube-api server logs and identify the root cause and fix the issue.
```
# kubectl get pods
Unable to connect to the server: net/http: TLS handshake timeout

# docker ps -a | grep apiserver
6955b6be9a89        ca9843d3b545           "kube-apiserver --ad…"   23 seconds ago       Exited (1) Less than a second ago                       k8s_kube-apiserver_kube-apiserver-controlplane_kube-system_b0c7fa5021cdd1d96107d4d0b0aa1b84_2
e3e5ee1254db        ca9843d3b545           "kube-apiserver --ad…"   About a minute ago   Exited (1) 36 seconds ago                               k8s_kube-apiserver_kube-apiserver-controlplane_kube-system_b0c7fa5021cdd1d96107d4d0b0aa1b84_1
2ed4ec96d244        k8s.gcr.io/pause:3.2   "/pause"                 About a minute ago   Up About a minute   

# docker logs 8f7dc5811bc2
W0724 16:24:39.766868       1 clientconn.go:1223] grpc: addrConn.createTransport failed to connect to {https://127.0.0.1:2379  <nil> 0 <nil>}. Err :connection error: desc = "transport: authentication handshake failed: x509: certificate signed by unknown authority". Reconnecting...
W0724 16:24:39.775775       1 clientconn.go:1223] grpc: addrConn.createTransport failed to connect to {https://127.0.0.1:2379  <nil> 0 <nil>}. Err :connection error: desc = "transport: authentication handshake failed: x509: certificate signed by unknown authority". Reconnecting...
W0724 16:24:40.771066       1 clientconn.go:1223] grpc: addrConn.createTransport failed to connect to {https://127.0.0.1:2379  <nil> 0 <nil>}. Err :connection error: desc = "transport: authentication handshake failed: x509: certificate signed by unknown authority". Reconnecting...
W0724 16:24:41.364354       1 clientconn.go:1223] grpc: addrConn.createTransport failed to connect to {https://127.0.0.1:2379  <nil> 0 <nil>}. Err :connection error: des

/// port 2379 is used by ETCD

# cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep etcd
    - --etcd-cafile=/etc/kubernetes/pki/ca.crt
    - --etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt
    - --etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key
    - --etcd-servers=https://127.0.0.1:2379
    
/// edcd has its own ca
// change
- --etcd-cafile=/etc/kubernetes/pki/ca.crt
// to
- --etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt


```

### Cert API

```
 cat /var/answers/akshay-csr.yaml
apiVersion: certificates.k8s.io/v1beta1
kind: CertificateSigningRequest
metadata:
  name: akshay
spec:
  signerName: kubernetes.io/kube-apiserver-client
  groups:
  - system:authenticated
  request: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1ZqQ0NBVDRDQVFBd0VURVBNQTBHQTFVRUF3d0dZV3R6YUdGNU1JSUJJakFOQmdrcWhraUc5dzBCQVFFRgpBQU9DQVE4QU1JSUJDZ0tDQVFFQXd5OGpqQzdWNHVwdkRYT3ZRUDZkQVZMMG1yMHdmVmNlQ01EZXJnclBWRUIzClZxZEFrRmUzQW5uaCtycE5WcDVyRXNBb2xKZTQyWmhmRDFHc0N1OXBYcVVDSXJFSnpGNnVXWEhBdzFXbjNJRHoKWTJyNTlzMC9rY2ZaM0JyN203cGFNU0NnS1loZWVweSt3OCt3aXlPMWNNNkR4N2d3b2E5SHdDRWEwVzFqUlF3cApFL0dGWHB5TjhpTjlNMEJ3QjdJMjFaY093eFBBQVlkVUF0Uk1EcmtzNlZGanVha3dlam0vVjd4czF0NlZLNzMwCi9qWW9aYTdWRUJkZmY3VVhvSWErTDg1UzFDMUhLNnQ3am1VMUlYcHhOWjZTU0VJU3MyRVZDWkY3bExtMW01ZDIKc204a3J5WUhLQzhrQVdvMVlhSHRNMzVKN1FLY0ZtYlc2czlzTmVoWjB3SURBUUFCb0FBd0RRWUpLb1pJaHZjTgpBUUVMQlFBRGdnRUJBR3hxVDRybjRrd2ZiQW8waW5Rb0tQbURuMkh3dnhjOHZQOUlRYXlRaVJtb3E4cjNSVnNOClR1SDVXaHdKMEd0bVBLQ1U0dG01V1R0VXNVZGdCNmtHRzRIZTFNdEJBSlE2T3UwZU9jWjl1SldLbkNxMHBPRXMKNzhKa3BjY0lRdG9GSW56Y1ovZlQ2ZmVCc3JiRFh5bVQxU1M1MXk5Ly9jQnJKQjJzMFVYcVg4WnF5T0FmanpLRQppWVE1MTNsSUs2bjJiWXlaRXQ2Q3VDeXg4Q0s1d3hwYU1rNTVncnovNm5EYUZNR0ZXS3RhOFRrQ1VGT1JNQmxqCnNndXBRTVFEL2k3U2JUZk4rNlArZkJJMFVsck5LQWczYmRyendWWmhKVkF6ZDJIV3dqREc0VzQ3N2JZeEI2ek8KVkRrVGkyWnE0WGs2TURWdE8zeTEwRlROM2dteG9WZnRseGc9Ci0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQo=
  usages:
  - digital signature
  - key encipherment
  - server auth
```

```
kubectl create -f /var/answers/akshay-csr.yaml

k get csr -A
NAME        AGE     SIGNERNAME                                    REQUESTOR                  CONDITION
akshay      27s     kubernetes.io/kube-apiserver-client           kubernetes-admin           Pending

kubectl certificate approve akshay

k get csr/agent-smith -o yaml | grep -A 2 groups:
  groups:
  - system:masters
  - system:authenticated

kubectl certificate deny agent-smith

 kubectl delete csr agent-smith

```

### Kubeconfig

- Access k8s api via cert
```
curl http://api-server:6443/api/v1/pods --key admin.key --cert admin.crt --cacert ca.crt
```
and via kubectl
```
kubectl get pods --server api-server:6443 --client-key admin.key --client-certificate admin.crt --certificate-authority ca.crt
```
or kubeconfig, by default in 
```
$HOME/.kube/config
```
or via cli
```
--kubeconfig config
```

Kubeconfig has 3 sections
- clusters
- - eg. production, dev, google
- contexts
- - eg admin@production, dev@google
- users
- - eg. Admin, DevUser, ProdUser

```
apiVersion: v1
kind: Config

clusters:
- name:
  cluster:
    certificate-authority:
    server:
    
contexts:
- name:
  context:
    cluser:
    user:

users:
- name:
  user:
    client-certificate:
    client-key:

```
- Current context is reflected in the file
```
kubectl config use-context my-context

apiVersion: v1
kind: Config
current-context: my-context
```

- A context can specify a namespace
```
    
contexts:
- name:
  context:
    cluser:
    user:
    namespace: my-namespace
```
- Certificates in kubeconfig should be a full path to the file, however you can also inline certificate information
```
# encode cert as base64
cat ca.crt | base64

clusters:
- name:
  cluster:
    certificate-authority-data: <base64-string>
    server:
    
# to decode
echo '<base64-string>' | base64 --decode
```

### API Groups
api's are organized into groups
```
/version
/api
/apis
/metrics
/healthz
/logs
```

- core group /api
- named group /apis
- going forward named groups will be used

hierarchy
```
named          
   - api group     eg. networking.k8s.io
     - resource   eg. networkpolicy
```

actions / verbs
- list, get, create, delete, update, watch 

- access the api via proxy
```
kubectl proxy

$ curl -k 127.0.0.1:8001
{
  "paths": [
    "/.well-known/openid-configuration",
    "/api",
    "/api/v1",
    "/apis",
    "/apis/",
    "/apis/admissionregistration.k8s.io",
    "/apis/admissionregistration.k8s.io/v1",
    "/apis/admissionregistration.k8s.io/v1beta1",
    "/apis/allspark.vmware.com",
    "/apis/allspark.vmware.com/v1alpha1",
    "/apis/apiextensions.k8s.io",
    "/apis/apiextensions.k8s.io/v1",
    "/apis/apiextensions.k8s.io/v1beta1",
    "/apis/apiregistration.k8s.io",
    ....
```
- List api groups
```
$ curl -k 127.0.0.1:8001/apis | jq .groups[].name

"apiregistration.k8s.io"
"apps"
"events.k8s.io"
"authentication.k8s.io"
"authorization.k8s.io"
"autoscaling"
"batch"
"certificates.k8s.io"
"networking.k8s.io"
"extensions"
"policy"
"rbac.authorization.k8s.io"
"storage.k8s.io"
"admissionregistration.k8s.io"
"apiextensions.k8s.io"
"scheduling.k8s.io"
"coordination.k8s.io"
"node.k8s.io"
"discovery.k8s.io"
"flowcontrol.apiserver.k8s.io"
"tsm.vmware.com"
"allspark.vmware.com"
"autoscaling.tsm.tanzu.vmware.com"
"client.cluster.tsm.tanzu.vmware.com"
"crd.antrea.tanzu.vmware.com"
"install.istio.io"
"kappctrl.k14s.io"
"ops.antrea.tanzu.vmware.com"
"security.antrea.tanzu.vmware.com"
"config.istio.io"
"core.antrea.tanzu.vmware.com"
"networking.istio.io"
"clusterinformation.antrea.tanzu.vmware.com"
"security.istio.io"
"stats.antrea.tanzu.vmware.com"
"controlplane.antrea.tanzu.vmware.com"
"metrics.k8s.io"
"networking.antrea.tanzu.vmware.com"
"system.antrea.tanzu.vmware.com"

```
- List storage resources
```
curl -k 127.0.0.1:8001/apis/storage.k8s.io/v1 | jq '.resources[].name'
"csidrivers"
"csinodes"
"storageclasses"
"volumeattachments"
"volumeattachments/status"
```





