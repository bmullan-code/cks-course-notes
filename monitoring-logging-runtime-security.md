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









