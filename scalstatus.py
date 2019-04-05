#!/usr/bin/python2

import os
import sys
from datetime import datetime
import yaml
import requests
import json
import argparse
import salt.client
import salt.config
import salt.runner 


# local import
from msg import Msg 
from scalchecks2 import BuildReq, Check 

try:
  parser = argparse.ArgumentParser(description="Check server's process status")
  parser.add_argument('-d', '--debug', dest='debug', action="store_true", default=False ,help='Set script in DEBUG mode ')
  parser.add_argument('-c', '--cont', dest='cont', action="store_true", default=False, help='If this option is set program wont quit if it finds missing servers, unexpected results may happend')
  parser.add_argument('-f', '--file', nargs=1, const=None ,help='Load yaml property file')
  parser.add_argument('-t', '--target', nargs=1, const=None ,help='Specify target daemon to check queue')
  parser.add_argument('-v', '--verbose', dest='verbose', action="store_true", default=False ,help='Set script in VERBOSE mode ')
  parser.add_argument('--zkcount', dest='zkcount',default=5 ,help='Specify number of ZK hosts')
  args=parser.parse_args()
except SystemExit:
  bad = sys.exc_info()[1]
  parser.print_help(sys.stderr)
  exit(9)

local = salt.client.LocalClient()

def disable_proxy():
  done=0
  for k in list(os.environ.keys()):
    if k.lower().endswith('_proxy'):
      del os.environ[k]
      done=1
  if done != 0:
    display.debug("Proxy has been disabled")



def check_zk():
  display.verbose("Checking zookeeper status ")
  #global args.zkcount
  zkcount=int(args.zkcount)
  follower=0
  leader=0
  # salt -G roles:ROLE_ZK_NODE cmd.run 'echo stat | nc localhost 2181|grep Mode'
  zk=local.cmd('roles:ROLE_ZK_NODE','cmd.run',['echo stat | nc localhost 2181|grep Mode'],expr_form="grain")
  display.debug("Zookeeper result {0}".format(zk))
  if len(zk.keys()) != zkcount:
    display.warning("Zookeeper does not run {0} instances".format(zkcount))
  for i in zk.keys():
    if not ':' in zk[i]:
      display.error('invalid response for {0} {1}'.format(i,zk[i]))
      continue
    if zk[i].split(':')[1].strip() == 'follower':
      follower=follower+1
    elif zk[i].split(':')[1].strip() == 'leader': 
      leader=leader+1
    else:
      display.error('unexpected state on zookeeper {0} {1}'.format(i,zk[i]))
  if follower != zkcount -1:
    display.error('unexpected number of zookeeper follower, expect {0} found {1}'.format(zkcount -1,follower))
  if leader != 1:
    display.error('Zookeeper number of master is {0}, one single leader is expected'.format(leader))
  display.info('{0} leader and {1} zookeeper follower found'.format(leader,follower),label="OK")
  return(0)

def check_elasticsearch(argument=None):
  es=local.cmd('roles:ROLE_SUP','cmd.run',['hostname'],expr_form="grain")
  target="localhost"
  url="http://{0}/api/v0.1/es_proxy/_cluster/health?pretty".format(target)
  try:
    r = requests.get(url)
  except requests.exceptions.RequestException as e:
    display.error("Error connecting to supervisor on localhost: {0}".format(target))
    display.debug("Error is  : \n{0}\n".format(e))
    return(1)
  if r.status_code == 200:
    status=json.loads(r.text)
  else:
    display.error("Elasticsearch not responding: Sup return non 200 response {0}".format(r.status_code))
    return(1)
  display.debug("Elasticsearch output".format(status))
  if status['status'] == 'green': 
    display.info("Elastic search status is green",label="OK")
  else:
    display.error("Elastic search status not  green")
    if "unassigned_shards" in status.keys():
      display.error("There are {0} unassigned shards on the cluster".format(status["unassigned_shards"]))
    if display.get() == "debug":
      print json.dumps(status,indent=2)

#defaultcheck={'svsd': [{'type': 'service'}, {'service': ['scality-svsd', 'scality-svsd']}, {'state': 'service.status'}], 'samba': [{'type': 'samba'}], 'smb': [{'type': 'service'}, {'service': ['sernet-samba-smbd', 'sernet-samba-nmbd']}], 'sfused': [{'type': 'service'}, {'service': 'scality-sfused'}, {'target': 'grain:roles:ROLE_CONN_CIFS'}]}
    
defaultcheck={'svsd': [{'type': 'service'}, {'service': ['scality-svsd']}, {'state': 'service.status'}], 'samba': [{'type': 'samba'}], 'smb': [{'type': 'service'}, {'service': ['sernet-samba-smbd', 'sernet-samba-nmbd']}], 'sfused': [{'type': 'service'}, {'service': 'scality-sfused'}, {'target': 'grain:roles:ROLE_CONN_CIFS'}]}

def main():
  display=Msg('info')
  #args = parser.parse_args()
  args,cli=parser.parse_known_args()
  if args.verbose == True:
    display.set('verbose')
  if args.debug==True:
    display.set('debug')

  disable_proxy()
  if args.file !=  None:
    work=BuildReq(definition=args.file[0])
  else:
    work=BuildReq(list=defaultcheck)
  work.display_parsed()
  todo=work.return_parsed() 
    

if __name__ == '__main__':
  main()
else:
  print "loaded"

