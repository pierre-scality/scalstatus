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
  def __init__(self,definition=None,list=None,msg='info'):
    self.display=Msg()
    self.display.set(msg)
    self.definition=definition
    self.inputdict={}
    self.list=list
    self.todo=[]
    self.local = salt.client.LocalClient()
    self.neededfields=['service','state','target']
    self.default_type={
    'samba' : { 'svclist' : ['sernet-samba-smbd','sernet-samba-nmbd'], 'target' : 'grain:roles:ROLE_CONN_CIFS' },
    'elasticsearch' : { 'svclist' : ['elasticsearch'], 'target' : 'grain:roles:ROLE_ELASTIC', 'function' : True }
    }
    self.srvlist = { 
    'scality-svsd' : {'service' : 'scality-svsd' , 'state' : ["service.enabled","service.status"] , 'target' : 'grain:roles:ROLE_SVSD' , 'function' : None },
    'scality-sfused' : {'service' : 'scality-sfused' , 'state' : ["service.enabled","service.status"] , 'target' : 'grain:roles:ROLE_CONN_SFUSED' , 'function' : None },
    'elasticsearch' : {'service' : 'elasticsearch' , 'state' : ["service.enabled","service.status"] , 'target' : 'grain:roles:ROLE_ELASTIC' , 'function' : True},
    'corosync' : {'service' : 'corosync' , 'state' : ["service.enabled","service.status"] , 'target' : 'grain:roles:ROLE_COROSYNC' , 'function' : None},
    'zookeeper' : {'service' : 'scality-sophiad' , 'state' : ["service.enabled","service.status"] , 'target' : 'grain:roles:ROLE_ZK_NODE' , 'function' : True}
    }
    self.mydefault= ['scality-svsd','scality-sfused','elasticsearch']

  def build_def_list(self,list):
    out=[]
    for i in list:
      if i not in self.srvlist:
        self.display.info('Service {0} is not defined, ignoring')
      else:
        out.append(self.srvlist[i]) 
    return(out)

  ''' output : {'default': [{'list': ['elasticsearch', 'corosync']}], 'svsd': [{'type': 'service'}, {'service': 'scality-svsd'}]  ...'''
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
      self.process_data()
    elif self.list != None:
      self.display.debug('using input list {0}'.format(list))
      self.inptudict=self.list
      self.process_data()
    else:
      self.display.info('Running defaults checks')
      self.todo=self.build_def_list(self.mydefault)
    #self.display_parsed()
    return(self.todo)
  
 
  def verify_entry(self,list):
    tocomplete=[]
    if not 'service' in list:
      self.display.verbose('Invalid entry: {0}'.format(list))
      return None
    for i in self.neededfields:
      if i not in list.keys():
        tocomplete.append(i)
    if tocomplete != []:
      if list['service'] not in self.srvlist.keys():
        self.display.error('Service {0} has no service : {0}'.format(list))
        return None
      for i in tocomplete:
        list[i] = self.srvlist[list['service']][i]  
      if 'function' in self.srvlist[list['service']]:
        list['function']=self.srvlist[list['service']]['function']
    return(list)

  ''' We receive a list from yaml and reformat as dict in todo list '''
  def process_data(self):
    self.display.debug('Entering process_data with {0}'.format(self.inputdict))
    for i in self.inputdict.keys():
      if i == "default":
        for default in self.inputdict['default'][0]['list']:
          temp={}
          temp['service']=default
          temp=self.verify_entry(temp)
          if temp:
            self.todo.append(temp)
      else:
        temp={}
        for el in self.inputdict[i]:
          for k in el.keys():
            temp[k]=el[k]
        temp=self.verify_entry(temp)
        if temp:
          self.todo.append(temp)
    return(0)

  def display_parsed(self):
    for i in  self.todo:
      print i
 

 
  def return_parsed(self):
    self.display.debug('List to be checked : {0}'.format(self.todo))
    return(self.todo)

class Check():
  def __init__(self,definition=None,cont=False,msg='info'):
    self.display=Msg()
    self.display.get()
    self.display.debug('initialising Check objectv')
    self.local = salt.client.LocalClient()
    self.cont=cont
    self.definition=definition
    self.service=[]
    self.state=""
    self.role=""
    self.salt_roles=self.get_all_grains('roles')
    self.inputdict={}
    #mydefault={ 'svsd': [{'type': 'service'}, {'service': 'scality-svsd'}, {'state': 'service.status'}], 'samba': [{'type': 'samba'}], 'smb': [{'type': 'service'}, {'service': ['sernet-samba-smbd', 'sernet-samba-nmbd']}], 'sfused': [{'type': 'service'}, {'service': 'scality-sfused'}, {'target': 'grain:roles:ROLE_CONN_CIFS'}]}
    # This list is for basic service checks 
    # service (as mentionned in yaml) : servicename, state to run, target targettype:saltformat target
    if self.definition != None:
      prop=BuildReq(definition[0],msg=self.display.get())
    else:
      prop=BuildReq(msg=self.display.get())
    self.inputdict=prop.parse_definition()
    self.display.debug('Dict to run is {0}'.format(self.inputdict))
    self.check_server_status()
    self.check_custom(self.inputdict)
     

  
  # Need at least name and type
  def check_custom(self,list):
    for i in list:
      self.display.debug("do check_custome against {0}".format(i)) 
      self.target=i['target']
      self.service=i['service']
      for this in i['state']:
        self.state=this
        ret=self.do_check_service()
        if ret == 99:
          break
      if not 'function' in i:
        self.display.debug("No function found :  {0}".format(i))
      else:
        if i['function'] != None:
          self.do_extended(self.service)
     
  def do_check_service(self,msg=""):
    if msg != "" :
      self.display.info(msg)
    # grain:roles:ROLE_CONN_SFUSED
    targetname=self.target.split(':',1)[1]
    targetwhich=self.target.split(':')[2]
    targettype=self.target.split(':')[0]
    if self.target.split(':')[1]  == 'roles':
      if targetwhich not in self.salt_roles:
        self.display.info("No server has the role {0}, ignoring request".format(targetwhich))
        return(99)
    self.display.debug("Checking state {1} for service {0} on target {2} which is {3}".format(self.service,self.state,targetname,targettype))
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

  def do_extended(self,what):
    self.display.get()
    func=ExtFunctions(what,msg=self.display.get())
    func.execit()

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

  def get_all_grains(self,which):
    grains=self.local.cmd('*','grains.get',[which])
    present=[]
    for k in grains.keys():
      l=grains[k]
      for this in l:
        if this not in present:
          present.append(this)
    return(present)

