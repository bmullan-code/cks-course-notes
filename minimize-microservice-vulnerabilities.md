## Minimizing Microservices Vulnerabilities


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


#### Lab
- install opa on linux
```
export VERSION=v0.27.1
curl -L -o opa https://github.com/open-policy-agent/opa/releases/download/${VERSION}/opa_linux_amd64
chmod 755 ./opa
./opa run -s &
```
- to test a rego policy
```
root@controlplane:~# ./opa test /root/example.rego 
1 error occurred during loading: /root/example.rego:3: rego_parse_error: illegal default rule (value cannot contain var)
        default allow = 
        ^
```
- load a policy
```
curl -X PUT --data-binary @file.rego http://localhost:8181/v1/policies/policyname

root@controlplane:~# curl -X PUT --data-binary @/root/sample.rego http://localhost:8181/v1/policies/policyname
{"client_addr":"127.0.0.1:50404","level":"info","msg":"Received request.","req_id":2,"req_method":"PUT","req_path":"/v1/policies/policyname","time":"2021-08-13T23:29:29Z"}
{"client_addr":"127.0.0.1:50404","level":"info","msg":"Sent response.","req_id":2,"req_method":"PUT","req_path":"/v1/policies/policyname","resp_bytes":2,"resp_duration":1.788821,"resp_status":200,"time":"2021-08-13T23:29:29Z"}
{}root@controlplane:~# 

```

### OPA in Kubernetes

- deployed with a ValidatingAdmissionWebhook
- configured with a ValidatingWebhookConfiguration

- An AdmissionReview (which contains the pod spec) is sent to the opa server which validates it against a set of policies implmented in rego
- an admissionReview object does not have additional context information other than what is in the new request
- to work around this you can in the rego import additional information eg.
```
import data.kubernetes.pods
```


### Secrets

- create a secret from literals
```
kubectl create secret generic db-secret --from-literal=DB_Host=sql01 --from-literal=DB_User=root --from-literal=DB_Password=password123
```
- using secrets from a pod
- https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-environment-variables

```
---
apiVersion: v1 
kind: Pod 
metadata:
  labels:
    name: webapp-pod
  name: webapp-pod
  namespace: default 
spec:
  containers:
  - image: kodekloud/simple-webapp-mysql
    imagePullPolicy: Always
    name: webapp
    envFrom:
    - secretRef:
        name: db-secret
```

#### Secrets Question 2 - Mock Exam 1
- how to extract data value from secret
```
kubectl get secrets/db-user-pass --template={{.data.password}}

kubectl get secret/a-safe-secret -n orion --template={{.data.CONNECTOR_PASSWORD}} | base64 -d
n0On3C@nH@ckM3

# other way
 kubectl -n orion get secrets a-safe-secret -o jsonpath='{.data.CONNECTOR_PASSWORD}' | base64 --decode

# mount as a volume

  volumes:
  - name: connector-password
    secret:
      defaultMode: 420
      secretName: a-safe-secret
      
 - mountPath: /mnt/connector/password
      name: connector-password
      readOnly: true


```

Article – Note on Secrets
Remember that secrets encode data in base64 format. Anyone with the base64 encoded secret can easily decode it. As such the secrets can be considered not very safe.

The concept of safety of the Secrets is a bit confusing in Kubernetes. The kubernetes documentation page and a lot of blogs out there refer to secrets as a “safer option” to store sensitive data. They are safer than storing in plain text as they reduce the risk of accidentally exposing passwords and other sensitive data. In my opinion it’s not the secret itself that is safe, it is the practices around it.

Secrets are not encrypted, so it is not safer in that sense. However, some best practices around using secrets make it safer. As in best practices like:

Not checking-in secret object definition files to source code repositories.
Enabling Encryption at Rest for Secrets so they are stored encrypted in ETCD.
Also the way kubernetes handles secrets. Such as:

A secret is only sent to a node if a pod on that node requires it.
Kubelet stores the secret into a tmpfs so that the secret is not written to disk storage.
Once the Pod that depends on the secret is deleted, kubelet will delete its local copy of the secret data as well.
Read about the protections and risks of using secrets here

Having said that, there are other better ways of handling sensitive data like passwords in Kubernetes, such as using tools like Helm Secrets, HashiCorp Vault. I hope to make a lecture on these in the future.

### gVisor

- linux kernel is complex
- access via syscalls
- not great for security, interacting with kernel increases attack surface
- eg. dirty cow
- seccomp / apparmor white/black list syscalls
- in a multi-tenant environment all tenants interact with the same kernel. 
- how to isolate access to the kernel
- this is what gVisor aims to achieve
- adds a layer between the kernel and user space applications.
- syscalls are made to the gvisor
- gvisor sandbox - 
- 1) sentry (app level kernel for containers, intercepts and responds to syscalls made by containers)
- 2) gofer - a file proxy for access to system files
- can be slightly slower

### katacontainers

- uses vms to isolate container
- each container is run in its own vm with its own kernel
- relies on nest virtualization which can be slow


### Runtimes

- eg. gvisor is a runtime, how to instruct pods to make use of the runteim
- done throught the RuntimeClass type
- contains name and handler eg.
```
apiVersion: node.k8s.io/v1beta1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
```
- handler would be kata for katacontainers
- to use the runtime specify in the pod spec
```
spec:
  runttimeClassName: gvisor
```


### MTLS - Mutual TLS

- server validate data is being sent by identified sender. 
- will verify identity of each party
- using mTLS to secure interpod communication
- uses istio or linkerd
- allow secure service to service communication.
- encrypt / decrypt
- multiple services 
- also known as service mesh
- Istio
- eg. webapp needs to talk to mysql pod
- with istio, a sidecar container is added to each pod
- request from webapp to mysql is intercepted by the sidecar and encrypted before sending to the sidecar in mysql and then passed to the container
- modes, when-possible or strict.



