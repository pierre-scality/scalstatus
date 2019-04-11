#!/usr/bin/python2.7

import os
import sys
from datetime import datetime
import yaml
import requests
import json
import salt.client
import salt.config
import salt.runner 


# local import
from msg import Msg 

local = salt.client.LocalClient()

class ExtFunctions():
  def __init__(self,obj,msg='info'):
    self.display=Msg()
    self.display.set(msg)
    self.obj=obj

  def execit(self):
    if self.obj == 'elasticsearch':
      self.check_elasticsearch()
    if self.obj == 'zookeeper':
      self.check_zk()
    else:
      self.display.error('Object {0} has no function implemented'.format(self.obj))

  def check_zk(self,zkcount=5):
    self.display.verbose("Checking zookeeper status ")
    #global args.zkcount
    follower=0
    leader=0
    # salt -G roles:ROLE_ZK_NODE cmd.run 'echo stat | nc localhost 2181|grep Mode'
    zk=local.cmd('roles:ROLE_ZK_NODE','cmd.run',['echo stat | nc localhost 2181|grep Mode'],expr_form="grain")
    self.display.debug("Zookeeper result {0}".format(zk))
    if len(zk.keys()) != zkcount:
      self.display.warning("Zookeeper does not run {0} instances".format(zkcount))
    for i in zk.keys():
      if not ':' in zk[i]:
        self.display.error('invalid response for {0} {1}'.format(i,zk[i]))
        continue
      if zk[i].split(':')[1].strip() == 'follower':
        follower=follower+1
      elif zk[i].split(':')[1].strip() == 'leader': 
        leader=leader+1
      else:
        self.display.error('unexpected state on zookeeper {0} {1}'.format(i,zk[i]))
    if follower != zkcount -1:
      self.display.error('unexpected number of zookeeper follower, expect {0} found {1}'.format(zkcount -1,follower))
    if leader != 1:
      self.display.error('Zookeeper number of master is {0}, one single leader is expected'.format(leader))
    self.display.info('{0} leader and {1} zookeeper follower found'.format(leader,follower),label="OK")
    return(0)

  def check_elasticsearch(self,argument=None):
    es=local.cmd('roles:ROLE_SUP','cmd.run',['hostname'],expr_form="grain")
    target="localhost"
    url="http://{0}/api/v0.1/es_proxy/_cluster/health?pretty".format(target)
    try:
      r = requests.get(url)
    except requests.exceptions.RequestException as e:
      self.display.error("Error connecting to supervisor on localhost: {0}".format(target))
      self.display.debug("Error is  : \n{0}\n".format(e))
      return(1)
    if r.status_code == 200:
      status=json.loads(r.text)
    else:
      self.display.error("Elasticsearch not responding: Sup return non 200 response {0}".format(r.status_code))
      return(1)
    self.display.debug("Elasticsearch output".format(status))
    if status['status'] == 'green': 
      self.display.info("Elastic search status is green",label="OK")
    else:
      self.display.error("Elastic search status not  green")
      if "unassigned_shards" in status.keys():
        self.display.error("There are {0} unassigned shards on the cluster".format(status["unassigned_shards"]))
      if self.display.get() == "debug":
        print json.dumps(status,indent=2)
    return(0)
