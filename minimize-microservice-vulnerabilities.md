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
- to check admission controllers in a kubeadm deployed cluster use
```
kubectl exec -it kube-apiserver-controlplane -n kube-system -- kube-apiserver -h | grep 'enable-admission-plugins'

kubectl exec -it kube-apiserver-controlplane -n kube-system -- kube-apiserver -h | grep 'enable-admission-plugins'
      --admission-control strings              Admission is divided into two phases. In the first phase, only mutating admission plugins run. In the second phase, only validating admission plugins run. The names in the below list may represent a validating plugin, a mutating plugin, or both. The order of plugins in which they are passed to this flag does not matter. Comma-delimited list of: AlwaysAdmit, AlwaysDeny, AlwaysPullImages, CertificateApproval, CertificateSigning, CertificateSubjectRestriction, DefaultIngressClass, DefaultStorageClass, DefaultTolerationSeconds, DenyEscalatingExec, DenyExecOnPrivileged, EventRateLimit, ExtendedResourceToleration, ImagePolicyWebhook, LimitPodHardAntiAffinityTopology, LimitRanger, MutatingAdmissionWebhook, NamespaceAutoProvision, NamespaceExists, NamespaceLifecycle, NodeRestriction, OwnerReferencesPermissionEnforcement, PersistentVolumeClaimResize, PersistentVolumeLabel, PodNodeSelector, PodSecurityPolicy, PodTolerationRestriction, Priority, ResourceQuota, RuntimeClass, SecurityContextDeny, ServiceAccount, StorageObjectInUseProtection, TaintNodesByCondition, ValidatingAdmissionWebhook. (DEPRECATED: Use --enable-admission-plugins or --disable-admission-plugins instead. Will be removed in a future version.)
```
- to enable the NamespaceAutoProvision controllers
```
Edit /etc/kubernetes/manifests/kube-apiserver.yaml 
yand add NamespaceAutoProvision admission controller to --enable-admission-plugins list
```
- Disable DefaultStorageClass admission controller
```
Add DefaultStorageClass to disable-admission-plugins in /etc/kubernetes/manifests/kube-apiserver.yaml
```
- as kube-apiserver is running as a pod you can check for the plugins with 
```
root@controlplane:~# ps -ef | grep kube-apiserver | grep admission-plugins
root     21584 21566  0 21:26 ?        00:00:09 kube-apiserver --advertise-address=10.42.136.8 --allow-privileged=true --authorization-mode=Node,RBAC --client-ca-file=/etc/kubernetes/pki/ca.crt --enable-admission-plugins=NodeRestriction,NamespaceAutoProvision --disable-admission-plugins=DefaultStorageClass
```

