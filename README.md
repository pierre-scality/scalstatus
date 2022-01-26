# This repo contains code to check ring status 

## dcs.py
This tool is running the campaign and display result is simple way.
Option -v show the results 
Option -d show everything 
Most of the system checks are based on grep -v so no result it show on success.
The script runs without option unless you want to check the raid card status.
In this case you need to add the -r <ctrl command> <Ctrl number>
ctrl command must be either ssacli or storcli (exactly)

## Usage 
```
# ./dcs.py  -r ssacli 2 
INFO            : All servers available
OK              : All minions have Check ES version : 6.7.1
OK              : Elastic search status is green
INFO            : Index summary archive 192 , daily 73 , other 8, total 273
OK              : Servers have all /var < 80%
ERROR           : NTP setting not ok on ausyd-mha1-cn13
ERROR           : NTP setting not ok on ausyd-mha1-cn14
OK              : NUMA setting
OK              : THP setting
ERROR           : TUNED setting not ok on ausyd-mha1-cn13
ERROR           : TUNED setting not ok on ausyd-mha1-cn14
OK              : IRQPS Process irqbalance is not running
ERROR           : IRQPS ONESHOT=1 setting not ok on ausyd-mha1-cn14
OK              : UUID UUID /scality
OK              : Battery status is OK
```



# scalstatus
This tool aims to provide a flexible way to monitor various ring components.
Still more POC than ready for prime time.

# mode
It can be used in 2 modes :
1.  default without argument which for now runs a fixed set of checks
(In the future it should use the grains to run standard checks)
2. with an input file in yaml where we can specify what/where to run 

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
* if type is not service it will use predefined service (Check class default_type dict)
* if tag is default it will use the list to run predefined checks hardcoded in  check.default_checks dictionnary

The default checks can run functions after checking all services.



