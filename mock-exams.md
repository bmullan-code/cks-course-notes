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



