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
class Service():
  def __init__(self,name=None,state=["service.enabled","service.status"],target=None,function={}):
    self.display=Msg()
    self.local = salt.client.LocalClient()
    self.state = state
    self.name = name
    self.target = target
    self.function = function

  def show(self):
    self.display.info("Params are {0} {1} {2} {3}".format(self.name,self.target,self.state,self.function)) 
 
  def check_service(self,msg=""):
    if self.name == None or self.state == None or self.target == None:
      self.display.error("Missing parameter in check_service")
      return(2)
    else:
      self.display.info("Entering check_service for {0}".format(self.name))
    targetname=self.target.split(':',1)[1]
    targettype=self.target.split(':')[0]
    if msg == "" :
      msg = "Checking {1} for {0} service".format(self.name,self.state)
    self.display.verbose(msg)
    for this in self.state:
      resp=self.local.cmd(targetname,this,[self.name],expr_form=targettype)
      bad=[]
      good=[]
      self.display.debug("Salt response {0}".format(resp))
      for srv in resp.keys():
        if resp[srv] == False:
          bad.append(srv)
        elif resp[srv] == True:
          good.append(srv)
      if bad != []:
        self.display.error("{0} {1} is not OK on {2}".format(self.name,this,','.join(bad))) 
      self.display.info("{0} {1} is ok on all servers ({2})".format(self.name,this,','.join(good)),label="OK") 
      self.display.debug("Servers list ({0})".format(','.join(bad))) 
    return(0)

class Scality_svsd(Service):
  def __init__(name):
    self.name = "scality-svsd"
    self.target = "grain:roles:ROLE_SVSD"

class Scality_sfused(Service):
  def __init__(name,state,target,function):
    self.name = "scality-sfused"
    self.target = "grain:roles:ROLE_SFUSED"

class Scality_elasticsearch(Service):
  def __init__(name,state,target,function):
    self.name = "elastic"
    self.target = "grain:roles:ROLE_ELASTIC"
    self.function = {'function':'check_elasticsearch'} 

class Scality_corosync(Service):
  def __init__(name,state,target,function):
    self.name = "corosync"
    self.target = "grain:roles:ROLE_SFUSED"

class Sernet_samba_smbd(Service):
  def __init__(name,state,target,function):
    self.name = "sernet-samba-smbd"
    self.target = "grain:roles:ROLE_CONN_CIFS"

class Sernet_samba_nmbd(Service):
  def __init__(name,state,target,function):
    self.name = "sernet-namba-smbd"
    self.target = "grain:roles:ROLE_CONN_CIFS"


class BuildReq():
  def __init__(self,definition=None,list=None):
    self.display=Msg()
    self.definition=definition
    self.inputdict={}
    self.list=list
    self.todo=[]
    self.default_type={
    'samba' : { 'svclist' : ['sernet-samba-smbd','sernet-samba-nmbd'], 'target' : 'grain:roles:ROLE_CONN_CIFS' },
    'elasticsearch' : { 'svclist' : ['elasticsearch'], 'target' : 'grain:roles:ROLE_ELASTIC', 'function' : True }
    }
    self.parse_definition()

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
    self.process_data()
    #self.display_parsed()
    return(self.todo)

  ''' We receive a list from yaml and reformat as dict in todo list '''
  def process_data(self):
    #print self.inputdict
    for i in self.inputdict.keys():
      if i == "default":
        self.display.warning('Default not implemented, ignoring : {0}'.format(self.inputdict['default']))
      else:
        temp={}
        for el in self.inputdict[i]:
          for k in el.keys():
            temp[k]=el[k]
        if isinstance(temp['service'],list):
          for i in temp['service']:
           print 'FINISH HERE'
        else:
          self.todo.append(temp)
    return(0)

  def display_parsed(self):
    for i in  self.todo:
      print i
  
  def return_parsed(self):
    self.display.debug('List to be checked : {0}'.format(self.todo))
    return(self.todo)

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
      mydefault={ 'svsd': [{'type': 'service'}, {'service': 'scality-svsd'}, {'state': 'service.status'}], 'samba': [{'type': 'samba'}], 'smb': [{'type': 'service'}, {'service': ['sernet-samba-smbd', 'sernet-samba-nmbd']}], 'sfused': [{'type': 'service'}, {'service': 'scality-sfused'}, {'target': 'grain:roles:ROLE_CONN_CIFS'}]}
      prop=BuildReq(list=mydefault)
      self.inputdict=prop.parse_definition()
    self.check_server_status()
    self.check_custom(self.inputdict)
    exit(0)    
      

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
      else:
        self.display.error("Type must be service : {0}".format(i))
        exit(2)
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

