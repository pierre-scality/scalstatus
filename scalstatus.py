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

#ZKNB=5 

# Salt client breaks logging class.
# Simple msg display class
class Msg():
  def __init__(self,level='info'):
    self.level=level
    self.valid=['info','debug','verbose','warning']

  def set(self,level):
    print "{0:15} : {1}".format('INFO','Setting loglevel to '+level)
    if level not in self.valid:
      self.display("not a valid level {0}".format(level))
      return(9)
    self.level=level

  def get(self):
    return self.level

  def verbose(self,msg,label=None):
    if self.level != 'info':
      if label != None:
        header=label
      else:
        header='VERBOSE'
      print "{0:15} : {1}".format(header,msg)

  def info(self,msg,label=None):
    if label != None:
      header=label
    else:
      header="INFO"
    print "{0:15} : {1}".format(header,msg)
  
  def error(self,msg,fatal=False):
    header="ERROR"
    print "{0:15} : {1}".format(header,msg)
    if fatal == True:
      exit(9)
  
  def warning(self,msg,fatal=False):
    header="WARNING"
    print "{0:15} : {1}".format(header,msg)
    if fatal:
      exit(9)

  def debug(self,msg):
    if self.level == "debug":
      header="DEBUG"
      print "{0:15} : {1}".format(header,msg)

  def showlevel(self):
    print "Error level is {0} : ".format(self.level)

display=Msg('info')


#args = parser.parse_args()
args,cli=parser.parse_known_args()
if args.verbose == True:
  display.set('verbose')
if args.debug==True:
  display.set('debug')

local = salt.client.LocalClient()

def disable_proxy():
  done=0
  for k in list(os.environ.keys()):
    if k.lower().endswith('_proxy'):
      del os.environ[k]
      done=1
  if done != 0:
    display.debug("Proxy has been disabled")

def check_service(service,operation,target,msg="",dict={}):
  if msg == "" :
    msg = "Checking {1} for {0} service".format(service,operation)
  display.verbose(msg)
  #svsd=local.cmd('roles:ROLE_SVSD','service.status',['scality-svsd'],expr_form="grain")
  #print target,operation,service
  resp=local.cmd(target,operation,[service],expr_form="grain")
  bad=[]
  good=[]
  display.debug("Salt response {0}".format(resp))
  for srv in resp.keys():
    if resp[srv] == False:
      bad.append(srv)
    elif resp[srv] == True:
      good.append(srv)
  if bad != []:
    display.error("{0} {1} is not OK on {2}".format(service,operation,','.join(bad))) 
    return(9)
  else:
    display.info("{0} {1} is ok on all servers ({2})".format(service,operation,','.join(good)),label="OK") 
    display.debug("Servers list ({0})".format(','.join(bad))) 
    return(1)
  return(0)


def check_fuse(type="scality-sfused",target="ROLE_CONN_SOFS",targettype='roles'):
  display.verbose("Checking {0} service , target {1}".format(type,target))
  fuse=check_service(type,"service.enabled",targettype+':'+target)
  fuse=check_service(type,"service.status",targettype+':'+target)


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

def check_es():
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
    display.error("Sup return non 200 response {0}".format(r.status_code))
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
    

def check_samba(target="roles:ROLE_CONN_CIFS",service=None):
  if service == None:
    service=['sernet-samba-smbd','sernet-samba-nmbd']
  for i in service:
    check_service(i,"service.enabled",target)
    check_service(i,"service.status",target) 

class Check():
  def __init__(self,definition=None,cont=False):
    self.cont=cont
    self.definition=definition
    self.service=[]
    self.state=""
    self.role=""
    self.inputdict={}
    # This list is for basic service checks 
    # service (as mentionned in yaml) : servicename, state to run, target targettype:saltformat target
    # a fourth argument will be treated as a function to run, 1 time after services have been checked.
    self.default_checks={
    'scality-svsd' : ['scality-svsd',['service.enabled','service.status'],'grain:roles:ROLE_SVSD'],
    'elasticsearch' : ['elasticsearch',['service.enabled','service.status'],'grain:roles:ROLE_ELASTIC','check_es'],
    'corosync' : ['corosync',['service.enabled','service.status'],'grain:roles:ROLE_COROSYNC'],
    'sernet-samba-smbd' : ['sernet-samba-smbd',['service.enabled','service.status'],'grain:roles:ROLE_CONN_CIFS'],
    'sernet-samba-nmbd' : ['sernet-samba-nmbd',['service.enabled','service.status'],'grain:roles:ROLE_CONN_CIFS']
    }
    # A type let run a service and add specifics function
    # format is service to run as a list and weather or not all a function (must be coded in run_type_function()
    # services must be defined in default_checks
    self.default_type={
    'samba' : { 'svclist' : ['sernet-samba-smbd','sernet-samba-nmbd'], 'target' : 'grain:roles:ROLE_CONN_CIFS' },
    'elasticsearch' : { 'svclist' : ['elasticsearch'], 'target' : 'grain:roles:ROLE_ELASTIC', 'function' : True }
    }
    if self.definition != None:
      self.custom = True 
      self.definition=definition[0]
      self.parse_definition()
      self.run_check()
    else:
      self.standard_check()
      exit(0)    
      
  def run_check(self):
    self.check_server_status()
    #print self.inputdict
    #print self.inputdict.keys()
    for i in self.inputdict.keys():
      if i == "default":
        if not 'list' in self.inputdict['default'][0]:
          display.warning('Entry {0} has no list skipping',format(self.inputdict['default']))
          continue
        self.do_default_check(self.inputdict['default'][0]['list'])
        continue
      self.build_check_from_default(self.inputdict[i])
    return(0)
 
  def build_check_from_default(self,list):	
    display.debug("build_check_from_default with {0} :".format(dict))
    self.service=None
    self.target=None
    self.statelist=None
    self.what="service"
    for el in list:
      if 'type' in el:
        self.what=el['type']
      if 'target' in el:
        self.target=el['target']
      if 'state' in el:
        self.statelist=el['state']
      if 'service' in el:
        self.service=el['service']
    
    if self.what != "service":
      if self.what not in self.default_type.keys():
        display.warning('service {0} not implemented'.format(self.type)) 
        display.verbose('know services : {0} '.format(', '.join(self.default_type.keys()))) 
        return(9)
      else:
        if 'svclist' in self.default_type[self.what]:
          for srv in self.default_type[self.what]['svclist']:
            self.run_std_check(srv)
        ## We reach here when using a default type to run a function
        if 'function' in self.default_type[self.what]:
          for fn in self.default_type[self.what]['function']:
            self.run_std_function(fn)
    else:
      self.run_check_from_list()


  def run_std_check(self,entry):
    self.service=self.default_checks[entry][0]
    self.statelist=self.default_checks[entry][1]
    self.target=self.default_checks[entry][2]
    for self.state in self.statelist:
      self.do_check_service( )


  def run_check_from_list(self): 
    display.debug("do_check_service {0} {1} {2} {3} before defaults".format(self.service,self.target,self.statelist,self.what))
    if self.service == None:
      display.error("service {0} has no service".format(self.service))
      return(3)
    

    if self.statelist == None:
      if self.service in self.default_checks.keys():
        self.statelist=self.default_checks[self.service][1]
      else:
        self.statelist=['service.enabled','service.status']
        display.info("service {0} no state to run, using enabled and status".format(self.service))
        #exit(3)
    
    if self.target == None:
      if self.service in self.default_checks.keys():
        self.target=self.default_checks[self.service][2]
      else:
        display.error("service {0} has no target".format(self.service))
        exit(3)

    
    display.debug("do_check_service {0} {1} {2} {3}".format(self.service,self.target,self.statelist,self.what))
    for self.state in self.statelist:
      self.do_check_service( )

  def do_default_check(self,list):
    for i in list:
      display.debug('do_default_check with {0}'.format(i))
      if i not in self.default_checks[i]:
        display.warning("check {0} not in default check list".format(i))
        continue
      self.service=self.default_checks[i][0]
      self.target=self.default_checks[i][2]
      for state in self.default_checks[i][1]:
        self.state=state
        self.do_check_service()
      if len(self.default_checks[i]) == 4:
        self.run_function_by_name(self.default_checks[i][3])
     
  def run_function_by_name(self,name):
    display.verbose('Running addtionnal check {0}'.format(name))
    if name == 'check_es':
      check_es()
 
  def do_check_service(self,msg=""):
    #targettype=self.target[0]
    #target=self.target[1:]
    if msg == "" :
      msg = "Checking {1} for {0} service on {2}".format(self.service,self.state,self.target)
    display.verbose(msg)
    targetname=self.target.split(':',1)[1]
    targettype=self.target.split(':')[0]
    #'roles:ROLE_SVSD','service.status',['scality-svsd'],expr_form="grain"
    #print targetname,self.state,str([self.service]),"expr_form="+str(targettype)
    resp=local.cmd(targetname,self.state,[self.service],expr_form=targettype)
    bad=[]
    good=[]
    display.debug("Salt response {0}".format(resp))
    for srv in resp.keys():
      if resp[srv] == False:
        bad.append(srv)
      elif resp[srv] == True:
        good.append(srv)
    if bad != []:
      display.error("{0} {1} is not OK on {2}".format(self.service,self.state,','.join(bad))) 
      return(9)
    else:
      display.info("{0} {1} is ok on all servers ({2})".format(self.service,self.state,','.join(good)),label="OK") 
      display.debug("Servers list ({0})".format(','.join(bad))) 
      return(1)
    return(0)
    exit(0)


  def parse_definition(self):  
    display.debug('open config file : {0}'.format(self.definition))
    try:
      f=open(self.definition)
    except:
      display.error('Can not open config file : {0}'.format(self.definition),fatal=True)
    try:
      y=yaml.safe_load(f)
    except:  
      display.error('Can not serialize config file : {0}'.format(self.definition),fatal=True)
    self.inputdict=y
    return(0)   

  def check_server_status(self):
    bad=[]
    display.info("Checking all servers availability")
    opts = salt.config.master_config('/etc/salt/master.d/60_scality.conf')
    opts['quiet'] = True
    runner = salt.runner.RunnerClient(opts)
    ret = runner.cmd('manage.status',[])
    display.debug(ret)
    if ret['down'] != []:
      bad=ret['down']
    display.debug("Server results {}".format(ret))
    if bad == []:
      display.verbose("All servers available")
      display.debug("Servers list {} ".format(','.join(ret['up'])))
    else:
      if not args.cont:
        display.error('Quitting because of missing servers ({0})'.format(','.join(bad)),fatal=True)
      else:
        display.warning('There are unavailable servers which may lead to unexpected results ({0})'.format(','.join(bad)))
    self.update_struct(bad,reverse=True) 
    self.update_struct(ret['up'],reverse=True) 
    return bad

  def update_struct(self,section=None,reverse=False):
    self.test={}

  #def run_check(self):
    

  def check_service(self,service,operation,target,targettype,msg=""):
    display.debug("check_service {0}".format(service))
    if msg == "" :
      msg = "Checking {1} for {0} service".format(service,operation)
    display.verbose(msg)
    resp=local.cmd(target,operation,[service],expr_form=targettype)
    bad=[]
    good=[]
    display.debug("Salt response {0}".format(resp))
    for srv in resp.keys():
      if resp[srv] == False:
        bad.append(srv)
      elif resp[srv] == True:
        good.append(srv)
    if bad != []:
      display.error("{0} {1} is not OK on {2}".format(service,operation,','.join(bad))) 
      return(9)
    else:
      display.info("{0} {1} is ok on all servers ({2})".format(service,operation,','.join(good)),label="OK") 
      display.debug("Servers list ({0})".format(','.join(bad))) 
      return(1)
    return(0)

   # list is indexed by hostname

  def check_svsd(self,type="scality-svsd",target="roles:ROLE_SVSD",targettype='grain'):
    display.verbose("Checking svsd service")
    svsd=self.check_service("scality-svsd","service.status",target,targettype)
    svsd=self.check_service("scality-svsd","service.enabled",target,targettype)
   
  def standard_check(self):
    self.check_server_status()
    self.check_svsd()
    check_zk()
    check_fuse()
    check_fuse(target="ROLE_CONN_CIFS")
    check_es()
    #check_corosync()
    check_samba()

def main():
  disable_proxy()
  if args.file ==  None:
    check=Check(cont=args.cont) 
    #Check.check_server_status()
  else:
    check=Check(definition=args.file,cont=args.cont) 

if __name__ == '__main__':
  main()
else:
  print "loaded"

