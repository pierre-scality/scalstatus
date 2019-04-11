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


from msg import Msg
from scalchecks2 import Check

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


display=Msg('info')


#args = parser.parse_args()
args,cli=parser.parse_known_args()
if args.verbose == True:
  display.set('verbose')
if args.debug==True:
  display.set('debug',silent=False)

local = salt.client.LocalClient()

def disable_proxy():
  done=0
  for k in list(os.environ.keys()):
    if k.lower().endswith('_proxy'):
      del os.environ[k]
      done=1
  if done != 0:
    display.debug("Proxy has been disabled")


def main():
  disable_proxy()
  if args.file ==  None:
    check=Check(cont=args.cont,msg=display.get()) 
    #Check.check_server_status()
  else:
    check=Check(definition=args.file,cont=args.cont,msg=display.get()) 

if __name__ == '__main__':
  main()
else:
  print "loaded"

