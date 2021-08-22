## Monitoring, Logging & Runtime Security

- Detect malicious activities
- Detect threats
- Detect all phases of attacks
- Perform deep analytical investigation
- immutability of containers
- use audit logs to monitor access

### Analytics of syscalls

- abnormal behavior, cyber attackes & breackes

- have to prepare for scenarios where containers are compromised
- the sooner we find out the better

### Falco

- Falco sees system calls from user space to kernel. 
- Falco uses eBPF which is less intrusive and safer
- System calls are analyzed by the library, and processed by the Falco policy engine
- Install falco
```
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list
apt-get update -y

apt-get -y install linux-headers-$(uname -r)

apt-get install -y falco

systemctl start falco

```
- can also run as a daemonset via k8s
```
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco

kubectl get pods
```
- use falco to detect threats
```
systemctl status falco

#run nginx
kubectl run nginx --image=nginx
kubectl get pods -o wide

# to view falco logs
journalctl -fu falco

# open a shell in the pod
kubectl exec -ti nginx -- bash

# should trigger an alert in falco

# also triggers
cat /etc/shadow

```

- falco rules
```
rules.yaml
- rule:
  desc:
  condition:
  output:
  priority
```
- example
```
rules.yaml
- rule: Detech shell inside a container
  desc: Alert if a shell such as bash is open
  condition: container.id != host and proc.name = bash
  output: Bash Shell Opened (user=%user.name %container.id)
  priority: WARNING
```
- example of filters
- - container.id
- - proc.name
- - fd.name
- - evt.type (open, accept etc)
- - user.name
- - conatiner.image.repository

https://falco.org/docs/rules/supported-fields/

- example that uses a list
```

rules.yaml
- list: linux_shells
  items: [bash, zsh, ksh,sh,csh]
- rule: Detech shell inside a container
  desc: Alert if a shell such as bash is open
  condition: container.id != host and proc.name in (linux_shells)
  output: Bash Shell Opened (user=%user.name %container.id)
  priority: WARNING
```
- example of a macro
```
- macro: container
  condition: container.id != host

- rule: Detech shell inside a container
  desc: Alert if a shell such as bash is open
  condition: container and proc.name in (linux_shells)
  output: Bash Shell Opened (user=%user.name %container.id)
  priority: WARNING
```
https://falco.org/docs/rules/default-macros/


#### Falco Configuration Files

- main file /etc/falco/falco.yaml
- logs 
```
journalctl -fu falco
```
- rules are specified in the file by variable *rules_file*
```
rules_file:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco_rules.local.yaml
  ...
```
- other config
```
json_output: false|true
log_stderr
log_syslog
log_level: info 
priority: debug # anything higher than this level will be logged
```
- output
```
stdout_output:
  enabled: true
file_output:
  enabled: true
  filename: /opt/falco/events.txt
program_output:
  enabled: true
  program: "jq '{text: .ouput} | curl -d @- -X POST https://hooks.slack.com/services/xxx"
http_output
  enabled: true
  url: htttp://some.url/some/path/
```
- changes made require a reload
```

```
- rules files
```
# default rules file, many builtin rules but we can add our own or override existing
# /etc/falco/falco_rules.yaml

# you should not make changes to this file as it will be overwritten by new versions
# instead add to 
# /etc/falco/falco_rules.local.yaml

# to reload rules files
# find the pid of falco process
cat /var/run/falco.pid
kill -1 $(cat /var/run/falco.pid)

```









