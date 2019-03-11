# scalstatus
scalstatus is a tool to check running components on a scality installation 

# property file 
''' prop ifile format
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

'''

