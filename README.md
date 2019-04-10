# scalstatus
This tool aims to provide a flexible way to monitor various ring components.


# mode
It can be used in 2 modes :
1 - default without argument which for now runs a fixed set of checks
(In the future it should use the grains to run standard checks)
2 - with an input file in yaml where we can specify what/where to run 

## Propery file structure
Format is like :
```
svsd:
  - type: service 
  - service: scality-svsd

sfused:
  - type: service
  - service: scality-sfused
  - target: grain:roles:ROLE_CONN_CIFS

default:
  - list:
    - elasticsearch
    - corosync

samba:
  - type: samba
```

The root of each section is a tag.
Then we can have 3 various types.
* if type is service => run a service check (support target to define salt target, and service for the service name)
service check service.enabled and service.status
* if type is not service it will use predefined service (Check class default_type dict)
* if tag is default it will use the list to run predefined checks hardcoded in  check.default_checks dictionnary

The default checks can run functions after checking all services.



