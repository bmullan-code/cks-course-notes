
- Minimize Base Image Footprint
- Image Security
- Secure your supply chain
- Use static analysis of workload
- scan images for known vulnerability


### Minimize Base Image

- Base images are specified in FROM in Dockerfile
- scan example
```
trivy image httpd
```


### Lab

- create a registry secret
```
kubectl create secret docker-registry private-reg-cred 
--docker-username=dock_user 
--docker-password=dock_password 
--docker-server=myprivateregistry.com:5000 
--docker-email=dock_user@myprivateregistry.com
```

### Whitelisting allowed registries

--enable-admissions-plugins
ImagePolicyWebhook
--admission-control-config-file=

```
# /etc/kubernetes/manifests/kube-apiserver.yaml

spec:
  containers:
  - command:
    - kube-apiserver
    - --advertise-address=10.38.2.9
    - --allow-privileged=true
    - --authorization-mode=Node,RBAC
    - --client-ca-file=/etc/kubernetes/pki/ca.crt
    - --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
    - --admission-control-config-file=/etc/kubernetes/pki/admission_configuration.yaml
    
```

### Static Analysis of workloads

- eg. kubesec (kubesec.io)
- analyze a given resource definition file and returns a score based on what it finds (eg. privilidged container)
```
kubesec scan pod.yaml
```
- install
```
wget https://github.com/controlplaneio/kubesec/releases/download/v2.11.0/kubesec_linux_amd64.tar.gz
tar -xvf  kubesec_linux_amd64.tar.gz
mv kubesec /usr/bin/
```


### trivy

- cve (commone vulnerability and exposures)
- install
```
#Add the trivy-repo
apt-get  update
apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list

#Update Repo and Install trivy
apt-get update
apt-get install trivy
```
- filter to high severity 
```
trivy image --severity=HIGH python:3.6.12-alpine3.11 > /root/python.txt
```
- scan a tar file and output json
```
trivy image --input alpine.tar --format json --output /root/alpine.json
```





