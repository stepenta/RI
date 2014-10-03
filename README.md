# mPlane (almost) full architecture implementation

This repository contains a fully working Client-Supervisor-Probe architecture.

This implementation is based on the "official" python Reference Implementation, but is gone through heavy modifications (mostly for the interface parts, while the internals -scheduler and model- are pretty much the same). The main changes made to the code are the following:
* Conversion from capability pull, specification push, to capability push, specification pull
* Implementation of Supervisor, that works as an HTTP server. Now, all the components interact only through it
* The whole system works on HTTPS

# Usage
After cloning this repository and installing all the libraries needed, you can run the code this way (run these commands from inside the RI folder):

```
Supervisor:
export MPLANE_CONF_DIR=./conf
python3 -m mplane.supervisor -c ./conf/supervisor-certs.conf -s 127.0.0.1 -p 8888

Probe (tStat proxy, that for now works without running tStat, returning fictitious results):
python3 -m mplane.tstat_proxy -T ./conf/runtime.conf -c ./conf/component-certs.conf -d 127.0.0.1 -p 8888

Client:
python3 -m mplane.client -c ./conf/client-certs.conf -d 127.0.0.1 -p 8888
```

There are more options available, you can show them using `-h`. The commands within the supervisor and the client are the same of the original RI, you can see a list of those using the `help` command

# Misc Informations
* The interactions between the Probe and the Supervisor, and between the Supervisor and the Client are compliant to [these directives](https://github.com/finvernizzi/mplane_http_transport)
* The configuration files are not changed from the original RI: you can set certificate paths from `conf/supervisor-certs.conf`, `conf/component-certs.conf` and `client-certs.conf`; and user-role-capability authorizations from `conf/users.conf` and `conf/caps.conf`
* Since we are still in develop and test phases, all the PKI keys are publicly available. That, of course, will be fixed as soon as this phase ends
* The scripts in the PKI folder allow you to generate your own certificate. It is strongly recommended to use the provided root-ca, and only generate your own client, component and supervisor certificates, so that we avoid several self-signed certificates that cannot cooperate.
* You will need the root-ca passphrase to generate certificates: send me a mail at stefano.pentassuglia@ssbprogetti.it and I'll tell you that.
