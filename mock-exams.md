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
      localHostProfile: profiles/audit.json
      
```
