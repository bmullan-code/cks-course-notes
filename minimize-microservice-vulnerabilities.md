## Minimizing Microservices Vulnerabilities

|  |  |  |
| ---- | ---- | ---- |
| Admission Controllers | Pod Security Policies | Open Policy Agent | 
| Managing Kubernetes Secrets | Container runtime | Implement Pod encryption by use of MTLS | 


### Security Contexts

- may be set at the pod or container level. 
```
spec:
  securityContext:
    runAsUser: 1000
```
- or
```
spec:
  containers:
  - securityContext:
      runAsUser: 1000
      capabilities:
        add: ["MAC_ADMIN"]
```
- lab: try running data command in pod
```
kubectl exec -it ubuntu-sleeper -- date -s '19 APR 2012 11:14:00'

controlplane $ kubectl exec -it ubuntu-sleeper -- date -s '19 APR 2012 11:14:00'
date: cannot set date: Operation not permitted
Thu Apr 19 11:14:00 UTC 2012
command terminated with exit code 1
```

### Admission Controllers

- every request through the api server it goes through authentication (usually certificates) 
- authorization is checked against RBAC
- but RBAC has limitations
- addmission controllers allow us to add additional security constraints
- eg. builtin admission controller "namespaceExists" which verifies the namespace exists for a request
- to see a list of controllers
```
kube-apiserver -h | grep enable-admission-plugins
```




