#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import os
import re
import sys
import logging
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
  parser.add_argument('-l', '--list', dest='listonly', action="store_true", default=False ,help='Do not execute but display all function name and id that would be excuted')
  parser.add_argument('-r', '--raid', dest='raid', nargs=2, metavar=('type', 'ctrlid') , help='tell which RAID controler to check and controler id\n. Controler can only be  ssa|storcli and ctrlid an integer')
  parser.add_argument('-t', '--target', nargs=1, const=None ,help='Specify target daemon to check queue')
  parser.add_argument('-v', '--verbose', dest='verbose', action="store_true", default=False ,help='Set script in VERBOSE mode ')
  parser.add_argument('--zkcount', dest='zkcount',default=5 ,help='Specify number of ZK hosts')
  args=parser.parse_args()
except SystemExit:
  bad = sys.exc_info()[1]
  parser.print_help(sys.stderr)
  exit(9)


# Salt client breaks logging class.
# Simple msg display class
class Msg():
  def __init__(self,level='info',logfile='/tmp/schek.out'):
    self.level=level
    self.logfile=logfile
    self.valid=['info','debug','verbose','warning'] 
    self.fd=open(self.logfile,"a")    

  def set(self,level):
    print("{0:15} : {1}".format('INFO','Setting loglevel to '+level))
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
      print("{0:15} : {1}".format(header,msg))

  def info(self,msg,label=None):
    if label != None:
      header=label
    else:
      header="INFO"
    print("{0:15} : {1}".format(header,msg))
  
  def error(self,msg,fatal=False):
    header="ERROR"
    print("{0:15} : {1}".format(header,msg))
    if fatal == True:
      exit(9)
 
  def raw(self,msg):
    print(msg)
 
  def warning(self,msg,fatal=False):
    header="WARNING"
    print("{0:15} : {1}".format(header,msg))
    if fatal:
      exit(9)

  def debug(self,msg):
    if self.level == "debug":
      header="DEBUG"
      print("{0:15} : {1}".format(header,msg))

  def showlevel(self):
    print("Error level is {0} : ".format(self.level))

  def tofile(self,function,msg):
    d=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header="{} : {} ".format(self.level,d)
    self.fd.write("{} : {} : {}".format(header,function,msg))

display=Msg('info')


#args = parser.parse_args()
args,cli=parser.parse_known_args()
if args.verbose == True:
  display.set('verbose')
if args.debug==True:
  display.set('debug')
  display.debug("Args : {} and {}".format(args,cli))

local = salt.client.LocalClient()

def disable_proxy():
  done=0
  for k in list(os.environ.keys()):
    if k.lower().endswith('_proxy'):
      del os.environ[k]
      done=1
  if done != 0:
    display.debug("Proxy has been disabled")

def root_priv():
  euid=os.geteuid()
  if euid != 0:
    display.error("You need root access to use this tool, current euid {}".format(euid))

class Check():
  def __init__(self,cont,listonly,eshost="localhost"):
    self.cont=cont
    self.eshost=eshost
    self.listonly=listonly 
    self.flist={} 
    opts = salt.config.master_config('/etc/salt/master.d/60_scality.conf')
    opts['quiet'] = True
    self.runner = salt.runner.RunnerClient(opts)
    self.tgtgrains='expr_form="grain"'
    self.sysctlsettings=[
    ["vm.swappiness",'1','='],
    ["net.core.somaxconn",'4096','>'],
    ["vm.min_free_kbytes",'2000000','>'],
    ["net.ipv4.tcp_tw_reuse",'1','='],
    ["net.ipv4.ip_local_port_range",'20480    65001','=']
    ]
    self.systemtest=[
    ["NTP",'timedatectl | grep NTP | grep -v yes'],
    ["NUMA",'cat /proc/cmdline | grep -v numa'],
    ["THP",'cat /proc/cmdline | grep -v transparent_hugepage=never'],
    ["TUNED",'tuned-adm active | grep -v latency-performance'],
    ["IRQPS",'ps -edf | grep   irqbalance | grep -v grep','Process irqbalance is not running'],
    ["IRQ",'grep ONESHOT  /etc/sysconfig/irqbalance |grep -v "^#" | grep -v ONESHOT=1','ONESHOT=1 setting'],
    ["UUID",'egrep -E /scality/.*\(disk\|ssd\).*  /etc/fstab | grep -v s3 | grep -vi UUID','UUID /scality']
    ]


  
  def __runtime(self,function,id): 
    if self.listonly==True:
      display.raw("{}:{}".format(function,id))
      exit()
    display.verbose("Running {}".format(function))

  # get a dict with minion:value and compare all of them
  # It sort the field defined in lst (lst=[a,b] => dict[a][b]) in a dict
  # The return dict will have a single line if all values are same
  def __compare_minion_json(self,dict,lst,expected="same"):
    #display.debug("Entering __dict_field {} {}".format(dict,lst))
    rez={}
    for k in dict.keys():
      jes=json.loads(dict[k])
      this=self.__dict_get(jes,lst)
      display.debug("__compare_dict minion {}  {}".format(k,this))
      if this not in rez.keys():
        rez[this]=[k]
      else:
        rez[this].append(k)
    #display.debug("__compare_dict return {}".format(rez))
    return(rez)
    
  # return the value of the dict from a list (as string) 
  def __dict_get(self,dict,lst):
    #display.debug("Entering __dict_get {} {}".format(dict,lst))
    for l in lst:
      #display.debug("LOOP __dict_get {} {}".format(dict,l))
      r=str(dict[l])
      dict=dict[l]
    return(r)
 
  def __analyse_minion_same(self,dict,test_string):
    for k in dict.keys():
      display.tofile(test_string,"{} : {}".format(k,dict[k]))
      retcode=True
      # if 1 keys all same 
      if len(dict.keys()) == 1 :
        display.info("All minions have {} : {}".format(test_string,k),label="OK")
      else:
        display.warning("all minions have not {} : {}".format(test_string,k))
        retcode=False
    return(retcode)

  def minion_status(self):
    self.__runtime('minion_status',1)
    retcode=True
    display.verbose("Checking minions status")
    saltout=self.runner.cmd('manage.status',[])
    display.tofile("minion status",saltout)
    if saltout['down'] != []:
      display.warning('There are unavailable servers which may lead to unexpected results ({0})'.format(','.join(saltout['down'])))
      display.info('some hosts not available {}'.format(saltout['down']),label='NOK')
      retcode=False
    else:
      display.info("All servers available")
      display.verbose("Servers list {} ".format(','.join(saltout['up'])))
    return(retcode)
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
 

  def es_query(self,request):
    display.debug("prepare to run es query : {}".format(request))
    url="http://{}/{}".format(self.eshost,request)
    try:
      r = requests.get(url)
    except requests.exceptions.RequestException as e:
      display.error("Error connecting to supervisor on localhost: {0}".format(target))
      display.debug("Error is  : \n{0}\n".format(e))
      return(1)
    if r.status_code != 200:
      display.error("Elasticsearch not responding: Sup return non 200 response {0}, query string {1}".format(r.status_code,request))
      return(1)
    display.debug("response for {} :\n {}".format(url,r.text))
    return(r)
 
  def check_es_status(self):
    url="/api/v0.1/es_proxy/_cluster/health?pretty"
    r=self.es_query(url)
    if r == 1: 
      display.error("Aborting check_es_status")
      return(1)
    status=json.loads(r.text)
    display.debug("check_es_status raw output :\n {}".format(status))
    if status['status'] == 'green':
      display.info("Elastic search status is green",label="OK")
    else:
      display.error("Elastic search status not  green")
      if "unassigned_shards" in status.keys():
        display.error("There are {0} unassigned shards on the cluster".format(status["unassigned_shards"]))
      if display.get() == "debug":
        print(json.dumps(status,indent=2))

  def check_es_indices(self):
    url="/api/v0.1/es_proxy/_cat/indices"
    r=self.es_query(url)
    if r == 1: 
      display.error("Aborting check_es_status")
      return(1)
    status=r.text
    l=[]
    nok,archive,daily,other=0,0,0,0
    redaily=("[0-9]{4}.[0-9]{2}.[0-9]{2}")
    isdaily=re.compile(redaily)
    for i in r.text.splitlines():
      l.append(i.split())
    for e in l:
      last=e
      idx=last[2]
      idxlast=idx.split('-')[-1]
      if last[0] != "green":
        nok+=1
      if idxlast == "archive":
        archive+=1
      elif isdaily.match(idxlast): 
        daily+=1
      else:
        other+=1
    if nok != 0:
      display.error("there are not green index : {} index".format(nok))
    display.info("Index summary archive {} , daily {} , other {}, total {}".format(archive,daily,other,archive+daily+other))

  def check_es_version(self):
    display.debug("entering check_es_version")
    saltout=local.cmd('roles:ROLE_ELASTIC','cmd.run',['curl -s -XGET http://localhost:9200'],expr_form="grain")
    display.tofile("check_es_version",saltout)
    # return dict of values with minions.
    display.debug("es output {}".format(saltout))
    dict=self.__compare_minion_json(saltout,['version','number'])
    self.__analyse_minion_same(dict,"Check ES version")

  def check_var_space(self):
    display.debug("entering check_var_space")
    saltout=local.cmd('*','disk.percent',['/var'])
    display.debug("/var test raw result :\n {}".format(saltout))
    good=[]
    bad=[]
    issue=[]
    ok=True
    for k in saltout.keys():
      if saltout[k] == {}:
        issue.append(k)
      else:
        v=int(saltout[k][:1])
        if v < 80:
          good.append(k)
        else:
          bad.append(k)
    if issue != []:
      display.error("/var probably not a partition (return empty list) : {}".format(issue))
      ok=False
    if bad != []:
      display.error("Following server have less than 80 free in /var : {}".format(issue))
      ok=False
    if ok == True:
      display.info("Servers have all /var < 80%",label="OK")
      display.verbose("Servers list ({})".format(good),label=None)   
    #else:
    #  display.verbose("Servers with /var < 80% ({})".format(good))   
        
  """ check_sys_grep test eachi line of the test list, the grep cmd must be empty to be ok """
  def check_sys_grep(self):
    display.debug("Entering check sys") 
    test=self.systemtest
    rez={}
    temp=[]
    for t in test:
      if len(t) > 2:
        msg = t[2]
      else:
        msg = "setting"
      saltout=local.cmd('*','cmd.run',[t[1]])
      display.verbose("test is '{}'".format(t[1]))
      display.debug("test {} :\n salt output {}".format(t[0],saltout))
      for e in saltout:
        if saltout[e] != '':
          if not t[0] in rez:
            rez[t[0]]=[]
          temp=[e,saltout[e]]
          rez[t[0]].append(temp)
          display.error("{} {} not ok on {}".format(t[0],msg,e))
          display.verbose("{}  : {}".format(e,saltout[e]))
    #for t in test:
      if not t[0] in rez.keys():
        display.info("{} {}".format(t[0],msg),label="OK")

  def check_raid(self,ctrl,id):
    display.debug("Entering check raid type {}".format(ctrl))
    supported_ctrl=('ssacli','storcli')
    if ctrl not in supported_ctrl:
      display.error("raid type {} not in {}".format(ctrl,supported_ctrl))
      exit(9)
    try:
      ctrlid=int(id)
    except ValueError:
      display.error("raid number not an interger : {}".format(ctrlid))
      exit(9)
 
    if ctrl == 'ssacli':
      cmd="ssacli ctrl slot={} show".format(ctrlid)
      saltout=local.cmd('roles:ROLE_STORE','cmd.run',[cmd],expr_form="grain")
      display.debug("Raid controller {} cmd {} ".format(ctrl,cmd))
      display.debug("sal output{}".format(saltout))
      good=[]
      bad=[]
      for srv in saltout.keys():
        line=saltout[srv].split('\n')
        if saltout[srv].split(':')[0].lstrip() == "Error":
          bad.append(srv)
          display.error("Server {} return an error {}".format(srv,saltout[srv]))
          continue 
        for L in line:
          l=L.split(':')
          if l[0].lstrip()  == 'Battery/Capacitor Status':
            s=l[1].lstrip()
            if s == 'OK':
              good.append(srv)
              display.debug("{} battery status is {}".format(srv,s))
            else:
              bad.append(srv)
              display.error("{} battery status is {}".format(srv,s))
      if bad == []:
        display.info("Battery status is {}".format(s),label="OK")
      return(0)
    elif ctrl == 'storcli':
      cmd='/opt/MegaRAID/storcli/storcli64 show J'
      saltout=local.cmd('roles:ROLE_STORE','cmd.run',[cmd],expr_form="grain")
      display.debug("Raid controller {} cmd {} ".format(ctrl,cmd))
      good=[]
      bad=[]
      for srv in saltout.keys():
        j=json.loads(saltout[srv])
        s=j['Controllers'][0]["Response Data"]["System Overview"][0]["BBU"]
        if s == 'Opt':
          good.append(srv)
          display.debug("{} battery status is {}".format(srv,s))
        else:
          bad.append(srv)
          display.error("{} battery status is {}".format(srv,s))
      if bad == []:
        display.info("Battery status is {}".format(s),label="OK")   
      return(0)
    else:
      display.error('Unknown raid type {}'.format(ctrl))  
      return(1)

  def check_sysctl(self):
    display.debug("Entering check sysctl") 
    test=self.sysctlsettings
    saltout=local.cmd('*','sysctl.show')
    bad=[]
    current={}
    good=[]
    for srv in saltout.keys():
      testok=True
      this=saltout[srv]
      for t in test:
        p=t[0]
        display.debug("Testing value {} on server {}".format(t,srv))
        if p not in this.keys():
          display.warning("Cannot test {} on {}".format(e,srv))
          curval="{}:{}".format(p,'NOT FOUND')
          testok=False
        else:
          curval="{}:{}".format(p,this[p])
          v=t[1]
          testok=value_check(this[p],v,t[2])
        if testok == True:
          display.verbose("OK srv {} sysctl {} = {}".format(srv,p,v)) 
        else:
          if srv not in bad:
            bad.append(srv)
            curval="{}:->>>{}".format(p,this[p])
            display.error("SYSCTL {} {}".format(srv,curval))
        if not srv in current.keys():
          current[srv]=[curval]
        else:
          current[srv].append(curval)
      if srv not in bad:
        display.verbose("{} sysctl settings".format(srv),label='OK')
        display.debug("\n{}".format(current[srv]))
    if bad == []:
      display.info("SYSCTL settings",label="OK")
    else: 
      display.error("sysctl not OK {}".format(bad))

def value_check(a,b,op):
  display.debug("COMPARE Values {}:{}:{}".format(a,b,op))
  # removing the multiple spaces to compare
  nonint=False
  if op == '=':
    a=" ".join(a.split())
    b=" ".join(b.split())
    if a != b:
      return False
  elif op == '>':
    try: a=int(a)
    except ValueError: nonint=True
    try: b=int(b)
    except ValueError: nonint=True
    if nonint:
      display.error("Trying to compare non int values :{}:{}:".format(a,b))
      return False 
    if int(a) < int(b):
      return False
  else:
    display.error("Unknow operator {}".format(op)) 
    return False
  return True



def check_json(j,p="equal"):
  js=json.loads(j)
  
       
    
def main():
  disable_proxy()
  root_priv()
  check=Check(cont=args.cont,listonly=args.listonly) 
  raid=args.raid
  # run all procs
  check.minion_status()
  check.check_es_version()
  check.check_es_status()
  check.check_es_indices()
  check.check_var_space()
  check.check_sysctl()
  check.check_sys_grep()
  if raid != None:
    check.check_raid(raid[0],raid[1])
      
        

if __name__ == '__main__':
  main()
else:
  print("loaded")


