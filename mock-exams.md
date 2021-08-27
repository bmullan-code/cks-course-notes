### Mock Exam 1 


#### Q4 Seccomp

```
# copy profile to the right place
ssh node01
    1  cat /root/CKS/audit.json 
    2  cp /root/CKS/audit.json /var/lib/kubelet/seccomp/profiles/audit.json

# pod yaml security context
 securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/audit.json
```

#### Q5 CIS Benchmark

```
- --authorization-mode=Node,RBAC
```

### Q6 Falco

```
# you should not make changes to this file as it will be overwritten by new versions
# instead add to 
# /etc/falco/falco_rules.local.yaml

# to reload rules files
# find the pid of falco process
cat /var/run/falco.pid
kill -1 $(cat /var/run/falco.pid)

```
- full answer
```
#Create /opt/security_incidents on node01
$ mkdir -p /opt/security_incidents

##Enable file_output in /etc/falco/falco.yaml
file_output:
  enabled: true
  keep_alive: false
  filename: /opt/security_incidents/alerts.log

#Add the updated rule under the /etc/falco/falco_rules.local.yaml and hot reload the Falco service on node01:
- rule: Write below binary dir
  desc: an attempt to write to any file below a set of binary directories
  condition: >
    bin_dir and evt.dir = < and open_write
    and not package_mgmt_procs
    and not exe_running_docker_save
    and not python_running_get_pip
    and not python_running_ms_oms
    and not user_known_write_below_binary_dir_activities
  output: >
    File below a known binary directory opened for writing (user=%user.name file_updated=%fd.name command=%proc.cmdline)
  priority: CRITICAL
  tags: [filesystem, mitre_persistence]

#To perform hot-reload falco use 'kill -1 /SIGHUP' on node01:
$ kill -1 $(cat /var/run/falco.pid)



```

#### Q8 Admission Controller
```

#Create the below admission-configuration inside /root/CKS/ImagePolicy directory in the controlplane
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: ImagePolicyWebhook
  configuration:
    imagePolicy:
      kubeConfigFile: /etc/admission-controllers/admission-kubeconfig.yaml
      allowTTL: 50
      denyTTL: 50
      retryBackoff: 500
      defaultAllow: false

#The /root/CKS/ImagePolicy is mounted at the path /etc/admission-controllers directory in the kube-apiserver. So, you can directly place the files under /root/CKS/ImagePolicy.
#---snippet of the volume and volumeMounts (already added to apiserver config) ---#
  containers:
  .
  .
  .
  volumeMounts:
  - mountPath: /etc/admission-controllers
      name: admission-controllers
      readOnly: true

  volumes:
  - hostPath:
      path: /root/CKS/ImagePolicy/
      type: DirectoryOrCreate
    name: admission-controllers
#---------------------------------------------------------------------------------# 



#Next, update the kube-apiserver command flags and add ImagePolicyWebhook to the enable-admission-plugins flag. Use the configuration file that was created in the previous step as the value of 'admission-control-config-file'. 
#Note: Remember, this command will be run inside the kube-apiserver container, so the path must be /etc/admission-controllers/admission-configuration.yaml (mounted from /root/CKS/ImagePolicy in controlplane)
    - --admission-control-config-file=/etc/admission-controllers/admission-configuration.yaml
    - --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook


```


### Mock Exam 2

#### Q3 - Service Accounts

- Dont mount the service account token
```
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: apps-cluster-dash
  name: apps-cluster-dash
  namespace: gamma
spec:
  containers:
  - image: nginx
    name: apps-cluster-dash
  serviceAccountName: cluster-view
  automountServiceAccountToken: false
```


