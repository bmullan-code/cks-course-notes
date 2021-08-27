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


