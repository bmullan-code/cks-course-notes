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

### More on Admission Controllers

- DefaultStorageClass admission controller is an example of a *mutating* admission controller as it will change/mutate the object before it is created.
- It check for storage class in a PVC request, if not present it will add a default one.
- A *validating admission controller* will validate a request and reject it if it does not pass some condition
- in order, mutating then validating.
- To implement our own functionality there are 2 webhook controllers, **MutatingAdmissionWebhook** and **ValidatingAdmissionWebhook**

### Webhook Controllers

- deploy a webhook server, implemented in any language.

- example in python
```
@app.route("/validate", methods=["POST"])
def validate():
...
@app.route("/mutate", methods=["POST"])
def mutate():
...
```
- then create an admission webhook
```
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: "pod-policy.example.com"
webhooks:
- name: "pod-policy.example.com"
  clientConfig:
    service:
      namespace: "webhook-namespace"
      name: "webhook-service"
    caBundle: "Ci0tLSO..."
  rules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      operations: ["CREATE"]
      resources: ["pods"]
      scope: "Namespaced"
```
### Webhook Lab

- create secret
```
kubectl -n webhook-demo create secret tls webhook-server-tls \
    --cert "/root/keys/webhook-server-tls.crt" \
    --key "/root/keys/webhook-server-tls.key"
```
- example webhook deployment
- source: https://github.com/stackrox/admission-controller-webhook-demo/blob/main/cmd/webhook-server/main.go

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-server
  namespace: webhook-demo
  labels:
    app: webhook-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: webhook-server
  template:
    metadata:
      labels:
        app: webhook-server
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1234
      containers:
      - name: server
        image: stackrox/admission-controller-webhook-demo:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 8443
          name: webhook-api
        volumeMounts:
        - name: webhook-tls-certs
          mountPath: /run/secrets/tls
          readOnly: true
      volumes:
      - name: webhook-tls-certs
        secret:
          secretName: webhook-server-tls
```
- create a service for the deployment
```
root@controlplane:~# cat /root/webhook-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: webhook-server
  namespace: webhook-demo
spec:
  selector:
    app: webhook-server
  ports:
    - port: 443
      targetPort: webhook-api
      
root@controlplane:~# k create -f /root/webhook-service.yaml 
service/webhook-server created
```
- create the MutatingWebhookConfiguration
```
root@controlplane:~# cat /root/webhook-configuration.yaml
apiVersion: admissionregistration.k8s.io/v1beta1
kind: MutatingWebhookConfiguration
metadata:
  name: demo-webhook
webhooks:
  - name: webhook-server.webhook-demo.svc
    clientConfig:
      service:
        name: webhook-server
        namespace: webhook-demo
        path: "/mutate"
      caBundle: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURQekNDQWllZ0F3SUJBZ0lVQk5iN2R3cWg4SzBtSmZoTlFjem1FQmF2UXNZd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0x6RXRNQ3NHQTFVRUF3d2tRV1J0YVhOemFXOXVJRU52Ym5SeWIyeHNaWElnVjJWaWFHOXZheUJFWlcxdgpJRU5CTUI0WERUSXhNRGd4TXpJeE5EQTBObG9YRFRJeE1Ea3hNakl4TkRBME5sb3dMekV0TUNzR0ExVUVBd3drClFXUnRhWE56YVc5dUlFTnZiblJ5YjJ4c1pYSWdWMlZpYUc5dmF5QkVaVzF2SUVOQk1JSUJJakFOQmdrcWhraUcKOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQW8zb2lOWEI3OHFOZXBtdHFvRkJkRys1SFFoOFQ2Rm9LckFlTQphTEg1a3YzbHpBTUtDQ2t4U3Z3c0Q4LzE2TVBnMVNSbzI4S0R3YmlNMWRYK1dMcnE3NEdxa2Jrak5qa0MvZmdOClRpL25MZ01QLzhYTTVjTUV1RXN1MytiM1pteHRHVERSUVBqbVVZbEFnTWFQNndkb2d5eXdDaXQ3TjEzYUhQS0UKSGh2TEZ5aU5SZExsVk9XOUluVXB0RGZ4YkNaV3NZVC9qWFNBcll6QTVXTDJwUTlMUnJrNVIrUERsSFFsemF5TAppVjdsbndDYk4za2RNY2tjOFR1a3M2djRPRWxVejMxMTNBeUlOOGJXNzJjYzZvdWhNYWluOXNncHh2RXRjdTVNCmkrWmVyNVdjd3VNY1NTSkFEZzhrbWIrS0pjdkJuUEZmZml1dTJlYkszNkN3U1pSZzdRSURBUUFCbzFNd1VUQWQKQmdOVkhRNEVGZ1FVanpIWW9hYlZuVHMrRGp4eXJWT3BvU3h6T0xFd0h3WURWUjBqQkJnd0ZvQVVqekhZb2FiVgpuVHMrRGp4eXJWT3BvU3h6T0xFd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBTkJna3Foa2lHOXcwQkFRc0ZBQU9DCkFRRUFITksvZnVaNXA2NE5RM2hTNjVvc0hFaDM1ajNDVlZGbndyY1NaM1Q3SUY4Q1N4V0piS3pmdEtDbGRnRGIKUHVhYjkzZFRSUncySkQ4WTJxa0wwR2dwMnJualhxRVU2SlRnS1U3ZE8xdTQyZU1QazExSmlleU5IaFZYUEdVZQpnQUdpeGlFWEViUEErWWVRUG9kSGZmSFBaekVCWGVpU0YxZmlUcWxVM2hPdFRZbisrZ01kMHZyVm9VWkM5MUJJCnpqajN4aW9yd0hxRjRXVnZlbnpUd3l1SlJDcXpCS0Fwb1haUlFOVmZiWDgxQlN6UUFmbWFhL3Q5c2RNQVVFaHoKSU1tVkV4S3ZuQ1ozQUlyRTJob1BWWjlyaUlpbk1CSGRuZmFoMHBVUHNkcGJSSk83VXpUWmh0WjhxM2NQUzVqNwpoREVheUxwVFU3RlpnaytURmpuRkxGY2VNdz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
    rules:
      - operations: [ "CREATE" ]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
```
- Testing it out
```
root@controlplane:~# cat /root/pod-with-defaults.yaml
# A pod with no securityContext specified.
# Without the webhook, it would run as user root (0). The webhook mutates it
# to run as the non-root user with uid 1234.
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-defaults
  labels:
    app: pod-with-defaults
spec:
  restartPolicy: OnFailure
  containers:
    - name: busybox
      image: busybox
      command: ["sh", "-c", "echo I am running as user $(id -u)"]
      
root@controlplane:~# k apply -f /root/pod-with-defaults.yaml
pod/pod-with-defaults created

# check securityContext added
root@controlplane:~# k get pod/pod-with-defaults -o yaml | grep -A 3 securityContext
        f:securityContext:
          .: {}
          f:runAsNonRoot: {}
          f:runAsUser: {}
--
  securityContext:
    runAsNonRoot: true
    runAsUser: 1234

```
- second test
```
root@controlplane:~# cat /root/pod-with-override.yaml
# A pod with a securityContext explicitly allowing it to run as root.
# The effect of deploying this with and without the webhook is the same. The
# explicit setting however prevents the webhook from applying more secure
# defaults.
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-override
  labels:
    app: pod-with-override
spec:
  restartPolicy: OnFailure
  securityContext:
    runAsNonRoot: false
  containers:
    - name: busybox
      image: busybox
      command: ["sh", "-c", "echo I am running as user $(id -u)"]
```

### Pod Security Policies

- limit how a pod is run, for example you might not want the following
```
spec:
  containers:
    securityContext:
      priviliged: True
      runAsUser: 0
      capabilities:
        add: ["SYS_TIME"]
```
- pod security policy is enabbled as an admission controller.
```
- --enable-admission-plugins=PodSecurityPolicy
```
- then create a PodSecurityPolicy object
```
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example-psp
spec:
  priviliged: false
  seLinux:
    rule: RunAsAny
  supplementalGroups
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
```
- requires a service account authorized with the psp
```
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: psp-example-role
rules:
- apiGroups: ["policy"]
  resources: ["podsecuritypolicies"]
  resourceNames: ["example-psp"]
  verbs: ["use"]
```

#### Lab
- enabble psp controller
```
vi /etc/kubernetes/manifests/kube-apiserver.yaml 

```
- example psp
```
root@controlplane:~# cat /root/psp.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example-psp
spec:
  privileged: false
  seLinux:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - configMap
  - secret
  - emptyDir
  - hostPath
```
- try to apply pod from above
```
root@controlplane:~#  cat /root/pod.yaml 
apiVersion: v1
kind: Pod
metadata:
    name: example-app
spec:
    containers:
        -
            name: example-app
            image: ubuntu
            command: ["sleep" , "3600"]
            securityContext:
              privileged: True
              runAsUser: 0
              capabilities:
                add: ["CAP_SYS_BOOT"]
    volumes:
    -   name: data-volume
        hostPath:
          path: '/data'
          type: Directory
          
          
root@controlplane:~# k apply -f /root/pod.yaml 
Error from server (Forbidden): error when creating "/root/pod.yaml": pods "example-app" is forbidden: PodSecurityPolicy: unable to admit pod: [spec.containers[0].securityContext.privileged: Invalid value: true: Privileged containers are not allowed spec.containers[0].securityContext.capabilities.add: Invalid value: "CAP_SYS_BOOT": capability may not be added]
root@controlplane:~# 
```
- notes
- RequiredDropCapabilities - The capabilities which must be dropped from containers. These capabilities are removed from the default set, and must not be added. Capabilities listed in RequiredDropCapabilities must not be included in AllowedCapabilities or DefaultAddCapabilities.

### OPA - Open Policy Agent

- see the rego playground
- also see rego tests
- 




