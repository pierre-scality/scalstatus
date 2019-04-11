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
# The code
* msg.py 
Msg class for error level and display msg
* scalchecks2.py
Defines class to prepare data to check and run checks 
* scalfunc.py
Defines the extended functions
* scalstatus.py
Main program to run 

