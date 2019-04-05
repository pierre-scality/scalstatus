#!/usr/bin/python2.7

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
from scalfunc import ExtFunctions


class BuildReq():
  def __init__(self,definition=None,list=None):
    self.display=Msg()
    self.local = salt.client.LocalClient()
    self.definition=definition
    self.list=list
    self.todo=[]
    self.default_checks={
    'scality-svsd' : ['scality-svsd',['service.enabled','service.status'],'grain:roles:ROLE_SVSD'],
    'scality-sfused' : ['scality-sfused',['service.enabled','service.status'],'grain:roles:ROLE_CONN_SFUSED'],
    'elasticsearch' : ['elasticsearch',['service.enabled','service.status'],'grain:roles:ROLE_ELASTIC',{'function':'check_elasticsearch'}],
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
 
  def open_definition(self):  
    self.display.debug('open config file : {0}'.format(self.definition))
    try:
      f=open(self.definition)
    except:
      self.display.error('Can not open config file : {0}'.format(self.definition),fatal=True)
      return(1)
    try:
      y=yaml.safe_load(f)
    except:  
      self.display.error('Can not serialize config file : {0}'.format(self.definition),fatal=True)
      return(1)
    self.inputdict=y
    return(0)  

  def parse_definition(self):
    if self.definition != None:
      self.open_definition() 
    elif self.list != None:
      self.display.debug('using input list {0}'.format(list))
      self.inputdict=self.list
    else:
      self.display.error('Neither file nor list specified')
      exit(9)
    self.process_file()
    #self.display_parsed()
    return(self.todo)

  def process_file(self):
    #print self.inputdict
    #print self.inputdict.keys()
    for i in self.inputdict.keys():
      if i == "default":
        if not 'list' in self.inputdict['default'][0]:
          self.display.warning('Entry {0} has no list skipping',format(self.inputdict['default']))
          continue
        self.process_default(self.inputdict['default'][0]['list'])
      else:
        self.process_std(self.inputdict[i])
    return(0)

  # this function handle the default section of propery file
  # the default entries must be in self.default_checks dict. 
  def process_default(self,list):
    for i in list:
      self.display.debug('process_default with {0}'.format(i))
      if i not in self.default_checks[i]:
        self.display.warning("check {0} not in default check list".format(i))
        continue
      # default entry are only services
      self.what='service'
      self.argv=None
      self.service=self.default_checks[i][0]
      self.target=self.default_checks[i][2]
      for state in self.default_checks[i][1]:
        self.state=state
        self.todo.append(self.add_to_list()) 
      if len(self.default_checks[i]) > 3:
        self.argv=self.default_checks[i][3]
        self.state=None
        self.what='argv'
        self.todo.append(self.add_to_list()) 
  
  def add_to_list(self):
    tmp={}
    tmp['type']=self.what
    tmp['service']=self.service
    # could loop on target if target is a list
    tmp['target']=self.target
    tmp['state']=self.state
    tmp['argv']=self.argv
    return(tmp)

  # process yml file for non dfault
  # purpose of this function is to let use default params 
  # like scality-sfused is run against role ROLE_CONN_FUSE 
  # as well as verifying params
  def process_std(self,liste):	
    self.display.debug("process_std with {0} :".format(liste))
    self.service=None
    self.target=None
    self.statelist=None
    self.argv=None
    self.what="service"
    for el in liste:
      if 'type' in el:
        self.what=el['type']
        if self.what != 'service': 
          if self.what not in self.default_type.keys():
            self.display.warning('type {0} not implemented, ignored'.format(el['type'])) 
            return None
          else:
            self.build_from_default_type()
            self.add_to_list() 
            return
      if 'target' in el:
        self.target=el['target']
      if 'state' in el:
        self.statelist=el['state']
      if 'service' in el:
        self.servicelist=el['service']
      if 'function' in el:
        self.argv={'function':el['function']}
    # Check if minimum params are ok
    if self.servicelist == None:
      self.display.warning('No service found, ignoring')
      return None
    if isinstance(self.servicelist,list):
      for i in self.servicelist:
        self.service=i
        self.complete_from_default()
    else: 
      self.service=self.servicelist
      self.complete_from_default()
    if isinstance(self.statelist,list):
      for i in self.statelist:
        self.state=i
        self.todo.append(self.add_to_list())
    else:
      self.state=self.statelist
      self.todo.append(self.add_to_list())

  def display_parsed(self):
    for i in self.todo:
      print i

  def complete_from_default(self):
    if self.what == None:
      self.what='service'
    if self.target == None:
      if not self.service in self.default_checks.keys():
        self.display.warning('Missing target, ignoring') 
      else:
        self.target=self.default_checks[self.service][2]
    if self.statelist == None:
      if not self.service in self.default_checks.keys():
        self.display.warning('Missing state, ignoring') 
      else:
        self.statelist=self.default_checks[self.service][1]
    if self.target == None or self.state == None:
      self.display.warning('Missing need argument {0} {1} {2}, ignored'.format(self.service,self.target,self.state))
      return None 
    return(0)

  def build_from_default_type(self):
    self.target=self.default_type[self.what]['target']
    for i in self.default_type[self.what]['svclist']:
      #self.what='service'
      self.service=i
      self.todo.append(self.add_to_list())
    if 'function' in self.default_type[self.what]:
      self.what='function'
      self.todo.append(self.add_to_list()) 

 
class Check():
  def __init__(self,definition=None,cont=False):
    self.display=Msg()
    self.ext=ExtFunctions()
    self.local = salt.client.LocalClient()
    self.cont=cont
    self.definition=definition
    self.service=[]
    self.state=""
    self.role=""
    self.inputdict={}
    # This list is for basic service checks 
    # service (as mentionned in yaml) : servicename, state to run, target targettype:saltformat target
    if self.definition != None:
      prop=BuildReq(definition[0])
      self.custom = True 
      self.inputdict=prop.parse_definition()
    #  self.check_server_status()
    #  self.check_custom(self.inputdict)
    else:
      mydefault={'default': [{'list': ['elasticsearch', 'corosync']}], 
                  'svsd': [{'type': 'service'}, {'service': 'scality-svsd'}, {'state': 'service.status'}], 'samba': [{'type': 'samba'}], 
                  'smb': [{'type': 'service'}, {'service': ['sernet-samba-smbd', 'sernet-samba-nmbd']}], 'sfused': [{'type': 'service'}, 
                  {'service': 'scality-sfused'}, {'target': 'grain:roles:ROLE_CONN_CIFS'}]}
      prop=BuildReq(list=mydefault)
      self.inputdict=prop.parse_definition()
    self.check_server_status()
    self.check_custom(self.inputdict)
    exit(0)    
      

  def run_std_check(self,entry):
    self.service=self.default_checks[entry][0]
    self.statelist=self.default_checks[entry][1]
    self.target=self.default_checks[entry][2]
    for self.state in self.statelist:
      self.do_check_service( )


  def run_check_from_list(self): 
    self.display.debug("do_check_service {0} {1} {2} {3} before defaults".format(self.service,self.target,self.statelist,self.what))
    if self.service == None:
      self.display.error("service {0} has no service".format(self.service))
      return(3)
    

    if self.statelist == None:
      if self.service in self.default_checks.keys():
        self.statelist=self.default_checks[self.service][1]
      else:
        self.statelist=['service.enabled','service.status']
        self.display.info("service {0} no state to run, using enabled and status".format(self.service))
        #exit(3)
    
    if self.target == None:
      if self.service in self.default_checks.keys():
        self.target=self.default_checks[self.service][2]
      else:
        self.display.error("service {0} has no target".format(self.service))
        exit(3)

    
    self.display.debug("do_check_service {0} {1} {2} {3}".format(self.service,self.target,self.statelist,self.what))
    for self.state in self.statelist:
      self.do_check_service( )
  
  def check_custom(self,list):
    for i in list:
      self.display.debug("do check_custome against {0}".format(i)) 
      if i['type'] == 'service':
        self.target=i['target']
        self.service=i['service']
        self.state=i['state']
        self.do_check_service()
        if not 'argv' in i:
          self.display.debug("Not argv found, should be there {0}".format(i.keys()))
          return()
      if i['argv'] != None:
        # Special action to process
        self.do_extended(i)
     
  def do_check_service(self,msg=""):
    if msg == "" :
      msg = "Checking {1} for {0} service on {2}".format(self.service,self.state,self.target)
    self.display.verbose(msg)
    targetname=self.target.split(':',1)[1]
    targettype=self.target.split(':')[0]
    resp=self.local.cmd(targetname,self.state,[self.service],expr_form=targettype)
    bad=[]
    good=[]
    self.display.debug("Salt response {0}".format(resp))
    for srv in resp.keys():
      if resp[srv] == False:
        bad.append(srv)
      elif resp[srv] == True:
        good.append(srv)
    if bad != []:
      self.display.error("{0} {1} is not OK on {2}".format(self.service,self.state,','.join(bad))) 
      return(9)
    else:
      self.display.info("{0} {1} is ok on all servers ({2})".format(self.service,self.state,','.join(good)),label="OK") 
      self.display.debug("BAD servers list ({0})".format(','.join(bad))) 
      return(1)
    return(0)
    exit(0)

  def do_extended(self,list):
    if 'argv' in list:
      if 'function' in list['argv']:
        ret=self.do_run_function(list['argv'])
        return(ret)
      else:
        self.display.debug('Not implemented {0}'.format(list))
    else:
      self.display.debug('Should not reach here {0}'.format(list))
      return(9)


  def do_run_function(self,argv):
    funct=argv['function']
    if 'args' in argv:
      argument == argv['args']
    else:
      argument = None
    if funct == 'check_elasticsearch':
      ret=self.ext.check_elasticsearch(argument) 
      return(ret)
  
  def check_server_status(self):
    bad=[]
    self.display.info("Checking all servers availability")
    opts = salt.config.master_config('/etc/salt/master.d/60_scality.conf')
    opts['quiet'] = True
    runner = salt.runner.RunnerClient(opts)
    ret = runner.cmd('manage.status',[])
    self.display.debug(ret)
    if ret['down'] != []:
      bad=ret['down']
    self.display.debug("Server results {}".format(ret))
    if bad == []:
      self.display.verbose("All servers available")
      self.display.debug("Servers list {} ".format(','.join(ret['up'])))
    else:
      if not args.cont:
        self.display.error('Quitting because of missing servers ({0})'.format(','.join(bad)),fatal=True)
      else:
        self.display.warning('There are unavailable servers which may lead to unexpected results ({0})'.format(','.join(bad)))
    self.update_struct(bad,reverse=True) 
    self.update_struct(ret['up'],reverse=True) 
    return bad

  def update_struct(self,section=None,reverse=False):
    self.test={}

  def check_service(self,service,operation,target,targettype,msg=""):
    self.display.debug("check_service {0}".format(service))
    if msg == "" :
      msg = "Checking {1} for {0} service".format(service,operation)
    self.display.verbose(msg)
    resp=self.local.cmd(target,operation,[service],expr_form=targettype)
    bad=[]
    good=[]
    self.display.debug("Salt response {0}".format(resp))
    for srv in resp.keys():
      if resp[srv] == False:
        bad.append(srv)
      elif resp[srv] == True:
        good.append(srv)
    if bad != []:
      self.display.error("{0} {1} is not OK on {2}".format(service,operation,','.join(bad))) 
    self.display.info("{0} {1} is ok on all servers ({2})".format(service,operation,','.join(good)),label="OK") 
    self.display.debug("Servers list ({0})".format(','.join(bad))) 
    return(0)

