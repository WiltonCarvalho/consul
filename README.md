# Consul Cluster With TLS
![image](https://user-images.githubusercontent.com/45881665/150701086-10a564f1-460d-44c3-94da-1863327cdf5a.png)

## Download Consul on all server and client nodes
```
set -a
CONSUL_VERSION="1.10.4"
CONSUL_URL="https://releases.hashicorp.com/consul"
CONSUL_ZIP="consul_${CONSUL_VERSION}_linux_amd64.zip"

curl -sSL ${CONSUL_URL}/${CONSUL_VERSION}/$CONSUL_ZIP -o $CONSUL_ZIP
unzip $CONSUL_ZIP
chown root:root consul
mv consul /usr/local/bin/
rm $CONSUL_ZIP

consul -autocomplete-install
complete -C /usr/local/bin/consul consul

useradd -s /bin/false -d /consul/config -c "Consul User" consul
mkdir -p /consul/config /consul/data
chown -R consul:consul /consul
```

## Initial configuration
## All config files generated on the first consul server
```
mkdir ~/consul_confs && cd ~/consul_confs

# Cretes the CA cert
consul tls ca create

# Variables to generate the a single cert to all servers
set -a
consul1=192.168.122.42
consul2=192.168.122.223
consul3=192.168.122.137
client1=192.168.122.27

# Create the server cert
consul tls cert create -server -dc dc1 \
-additional-ipaddress=$consul1 \
-additional-ipaddress=$consul2 \
-additional-ipaddress=$consul3 \
-additional-dnsname=consul-1.dc1.consul \
-additional-dnsname=consul-2.dc1.consul \
-additional-dnsname=consul-3.dc1.consul

# Create the secret key for encryption
consul keygen > secret.key

# Variable to generate the tokens
tokens_master=$(uuidgen)
tokens_agent=$(uuidgen)
tokens_register=$(uuidgen)
secret=$(cat secret.key)
```

## Generate the server config file
```
cat <<EOF> server.hcl
# Consul Server
datacenter = "dc1"
data_dir = "/consul/data"
ca_file = "/consul/config/consul-agent-ca.pem"
cert_file = "/consul/config/dc1-server-consul-0.pem"
key_file = "/consul/config/dc1-server-consul-0-key.pem"
verify_incoming = false
verify_incoming_rpc = true
verify_outgoing = true
verify_server_hostname = true
retry_join = ["$consul1", "$consul2", "$consul3"]
log_level = "INFO"
bind_addr = "0.0.0.0"
client_addr = "0.0.0.0"
acl = {
  enabled = true
  default_policy = "deny"
  enable_token_persistence = true
  down_policy = "extend-cache"
  tokens {
    master = "$tokens_master"
  }
}
performance {
  raft_multiplier = 1
}
server = true
ui = true
bootstrap_expect = 3
connect = {
  enabled = true
}
ports = {
  https = 8501
  http = -1
}
auto_encrypt = {
  allow_tls = true
}
encrypt = "$secret"
EOF
```
## Fix file permissions
```
touch consul.env
chmod 600 *-key.pem secret.key
chown -R consul:consul ~/consul_confs
```

## Copy the files to all 03 servers
```
# consul-1
cp -a consul-agent-ca.pem /consul/config/
cp -a dc1-server-consul-0* /consul/config/
cp -a server.hcl /consul/config/
cp -a consul.env /consul/config/

# consul-2
tar cvpO -C /consul/config . | ssh ubuntu@$consul2 'sudo tar xvp -C /consul/config'

# consul-3
tar cvpO -C /consul/config . | ssh ubuntu@$consul3 'sudo tar xvp -C /consul/config'
```
## Generate the systemd file on all 03 servers
## Change adv_interface to the primary interface of the node
```
adv_interface=ens3

cat <<EOF> /etc/systemd/system/consul.service
[Unit]
Description="HashiCorp Consul - A service mesh solution"
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/consul/config/server.hcl

[Service]
EnvironmentFile=/consul/config/consul.env
User=consul
Group=consul
ExecStart=/usr/local/bin/consul agent -config-dir=/consul/config -advertise '{{ GetInterfaceIP "$adv_interface" }}'
ExecReload=/bin/kill --signal HUP \$MAINPID
KillMode=process
KillSignal=SIGTERM
Restart=on-failure
LimitNOFILE=65536
SuccessExitStatus=0 1

[Install]
WantedBy=multi-user.target
EOF
```

## Enable and start the service on all 03 servers
```
systemctl daemon-reload
systemctl enable consul
systemctl start consul
```

## Check if acl is working
```
consul acl token list
```

## Access the Consul Web UI
https://192.168.122.42:8501/ui
- Use the Master Token to log in


## Create the agent policy
```
cat <<'EOF'> agent-policy.hcl
node_prefix "" {
   policy = "write"
}
service_prefix "" {
   policy = "read"
}
EOF

consul acl policy create -name "agent-token" -description "Agent Token Policy" -rules @agent-policy.hcl

consul acl token create -description "Agent Token" -policy-name "agent-token" -secret=$tokens_agent
```

## Create the service register policy
```
cat <<'EOF'> register-policy.hcl
service_prefix "" {
  policy = "write"
}
EOF

consul acl policy create -name "register-token" -description "Register Token Policy" -rules @register-policy.hcl

consul acl token create -description "Register Token" -policy-name "register-token" -secret=$tokens_register
```

## Create the anonymous policy to be able to query DNS
```
cat <<'EOF'> anonymous-read.hcl
node_prefix "" {
  policy = "read"
}
service_prefix "" {
  policy = "read"
}
EOF

consul acl policy create -name anonymous-read -rules @anonymous-read.hcl

consul acl token update -id anonymous -policy-name=anonymous-read
```


## Generate the client config file
```
cat <<EOF> client.hcl
# Consul Client
datacenter = "dc1"
data_dir = "/consul/data"
enable_local_script_checks = true
enable_script_checks  = true
leave_on_terminate = true
rejoin_after_leave = true
retry_join = ["$consul1", "$consul2", "$consul3"]
log_level = "INFO"
bind_addr = "0.0.0.0"
client_addr = "0.0.0.0"
server = false
ui = false
ports {
  https = 8501
  http = -1
}
connect {
  enabled = true
}
verify_incoming = false
verify_incoming_rpc = true
verify_outgoing = true
verify_server_hostname = true
ca_file = "/consul/config/consul-agent-ca.pem"
auto_encrypt = {
  tls = true
}
encrypt = "$secret"
check_update_interval = "0s"
acl = {
  enabled = true
  default_policy = "deny"
  down_policy = "extend-cache"
  enable_token_persistence = true
  tokens {
    agent = "$tokens_agent"
  }
}
performance {
  raft_multiplier = 1
}
EOF
```

## Copy the client config to the clients
```
tar cvpO -C ~/consul_confs client.hcl consul.env consul-agent-ca.pem | ssh ubuntu@$client1 'sudo tar xvp -C /consul/config'
```

## Generate the systemd file on all clients
## Change adv_interface to the primary interface of the node
```
adv_interface=ens3

cat <<EOF> /etc/systemd/system/consul.service
[Unit]
Description="HashiCorp Consul - A service mesh solution"
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/consul/config/client.hcl

[Service]
EnvironmentFile=/consul/config/consul.env
User=consul
Group=consul
ExecStart=/usr/local/bin/consul agent -config-dir=/consul/config -advertise '{{ GetInterfaceIP "$adv_interface" }}'
ExecReload=/bin/kill --signal HUP \$MAINPID
KillMode=process
KillSignal=SIGTERM
Restart=on-failure
LimitNOFILE=65536
SuccessExitStatus=0 1

[Install]
WantedBy=multi-user.target
EOF
```

## Enable and Start the consul service on the clients
```
systemctl daemon-reload
systemctl enable consul
systemctl start consul
```
## Test the service register on a client
```
# Create the service register config
NGINX_IP=192.168.122.27
cat <<EOF> nginx.hcl
service {
  name = "nginx"
  id = "nginx-1"
  port = 80
  address = "$NGINX_IP"
  check {
    id       = "nginx-check"
    http     = "http://$NGINX_IP:80/"
    method   = "GET"
    interval = "1s"
    timeout  = "1s",
    DeregisterCriticalServiceAfter = "10m"
  }
}
EOF
```
## Load the consul variables to connect via HTTPS and use the tokens_register
```
export CONSUL_HTTP_ADDR=https://172.17.0.1:8501
export CONSUL_HTTP_SSL_VERIFY=false
export CONSUL_HTTP_TOKEN=35cf79a3-e556-4926-90ff-c6401f493d1c
```

## Register the service
```
consul services register nginx.hcl
```

## Test the dns service discovery
```
dig @127.0.0.1 -p 8600 nginx.service.consul srv
dig @127.0.0.1 -p 8600 _nginx._tcp.service.consul srv
```

## Deregister the service
```
consul services deregister nginx.hcl
```



## Some tests with cURL
```
############################# RASCUNHOS #######################################
cat <<'EOF'> web.json
{
  "id": "web1",
  "name": "web1",
  "port": 80,
  "check": {
    "name": "ping check",
    "args": ["ping", "-c1", "learn.hashicorp.com"],
    "interval": "30s",
    "status": "passing",
    "DeregisterCriticalServiceAfter": "10m"
  }
}
EOF

curl -v -k -H "X-Consul-Token: a45abcfb-3687-9b2c-e120-5c9ec62ea8db" -X PUT -d @web.json https://localhost:8501/v1/agent/service/register

curl -v -k -H "X-Consul-Token: a45abcfb-3687-9b2c-e120-5c9ec62ea8db" -X PUT https://localhost:8501/v1/agent/service/deregister/web1


############################### Legacy ACL ###############################
cat <<'EOF'> acl.json
{
  "Name": "Test",
  "Type": "client",
  "Rules": "service \"\" { policy = \"write\" }",
  "ID": "A9955E0C-8C96-4F60-8974-716B41B4C55B"
}
EOF
curl -v -k -H "X-Consul-Token: 3300efd0-e964-13c7-aaa9-a8f722426c25" -X PUT -d @acl.json https://localhost:8501/v1/acl/create

#############################3
curl -k -X PUT -d '{ "ID": "web1"}' https://localhost:8501/v1/agent/service/deregister

curl -k -X PUT https://localhost:8501/v1/agent/service/deregister/web1

--cacert /consul/config/consul-agent-ca.pem --resolve 'consul.example.com:8501:127.0.0.1'
#############################
aws secretsmanager update-secret --secret-id $CONSUL_CA_SECRET_ARN \
--secret-string file://consul-agent-ca.pem \
--region $AWS_REGION
aws secretsmanager update-secret --secret-id $CONSUL_GOSSIP_SECRET_ARN \
--secret-string file://secret.key \
--region $AWS_REGION

curl -s -k -H "X-Consul-Token:${CONSUL_HTTP_TOKEN}" ${CONSUL_HTTP_ADDR}/v1/connect/ca/roots?pem=true
```
