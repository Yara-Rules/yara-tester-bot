#!/usr/bin/env python
# encoding: utf-8
#
# Yararules checker Bot
# Tool to check yararules.com repo
# Copyright (C) 2016 @jovimon
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see [http://www.gnu.org/licenses/].

__author__ = '@jovimon'
__version__ = 0.6

import requests
import telegram
import ConfigParser
import sys
import time
import logging
import random
import git
import os
import subprocess
import shlex
import string
import re
import linecache
import json
from daemon import runner

class YaraBot():
   
  def __init__(self, argv):
    self.stdin_path = '/dev/null'
    self.stdout_path = '/dev/null'
    self.stderr_path = '/dev/null'
    self.script_path = os.path.dirname(os.path.realpath(__file__))
    self.pidfile_path = self.script_path  + '/' +  argv[0].split('.')[0] + '.pid'
    self.pidfile_timeout = 5

    # Strip the script name
    self.my_name = argv[0].split('.')[0]
    # Default config file to be used
    self.cfg_file = self.my_name + '.cfg'

    # Read config file
    self.config = ConfigParser.ConfigParser()
    self.config.read(self.cfg_file)

    # Load config options
    self.logfile = self.config.get('Log','logfile')
    self.loglevel = self.config.getint('Log','loglevel')

    # Create file logger
    self.logger = logging.getLogger("DaemonLog")
    self.logger.setLevel(self.loglevel)
    self.formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(module)s - %(message)s")
    self.handler = logging.FileHandler(self.logfile)
    self.handler.setFormatter(self.formatter)
    self.logger.addHandler(self.handler)
  #  logging.basicConfig(filename=logfile, format='%(asctime)s | %(levelname)s | %(module)s | %(message)s', level=loglevel,  datefmt='%Y%m%d %H:%M:%S')

    self.logger.warning("Starting %s Telegram Bot", self.my_name)

    # Create bot
    self.bot_token = self.config.get('Bot','token')
    self.bot = telegram.Bot(self.bot_token)

    # Warn if no chat_id configured
    if self.config.has_option('Bot','chat_id'):
      #chat_id = config.getint('Bot','chat_id')
      self.chat_id = json.loads(self.config.get("Bot","chat_id"))
      self.logger.info('chat_id found. Only updates from your chat_id will be taken care of.')
    else:
      self.chat_id = []
      self.logger.info('chat_id not found. Anyone can interact with your chat. Proceed with caution.')
           
  def run(self):
    try:
      LAST_UPDATE_ID = self.bot.getUpdates()[-1].update_id
    except IndexError:
      LAST_UPDATE_ID = None

    while(True):

      try:
        for update in self.bot.getUpdates(offset=LAST_UPDATE_ID, timeout=30):
          message = update.message.text.encode('utf-8')
          bot_chat_id = update.message.chat.id
          update_id = update.update_id

          self.logger.warning(update)

          if self.chat_id != [] and bot_chat_id not in self.chat_id:
            LAST_UPDATE_ID = update_id + 1
            continue
         
          if '/fullcheck' in message:
            status = self.check_syntax()
            for item in status:
              self.bot.sendMessage(chat_id = bot_chat_id, text=item , parse_mode='HTML') #parse_mode=telegram.ParseMode.MARKDOWN
              time.sleep(0.5)

          elif '/check' in message:
            status = self.check_syntax_nowarning()
            for item in status:
              self.bot.sendMessage(chat_id = bot_chat_id, text=item , parse_mode='HTML') #parse_mode=telegram.ParseMode.MARKDOWN
              time.sleep(0.5)

          elif '/test' in message:
            status = self.ruleset_test()
            for item in status:
              self.bot.sendMessage(chat_id = bot_chat_id, text=item , parse_mode='HTML') #parse_mode=telegram.ParseMode.MARKDOWN
              time.sleep(0.5)

          LAST_UPDATE_ID = update_id + 1
      except Exception as e:
        self.logger.error(sys.exc_info())
        time.sleep(10)



  def update_from_git(self, repo_dir):
    myrepo = git.Repo(repo_dir)
    o = myrepo.remotes.origin
    mypull = o.pull()
    mycommit = myrepo.commit('HEAD')

    commit_id = mycommit
    commit_author = mycommit.committer.name
    commit_date = time.strftime("%a, %d %b %Y %H:%M", time.gmtime(mycommit.committed_date))

    header = "Commit <em>%s</em>\nby <strong>%s</strong> on <em>%s</em>" % (commit_id, commit_author, commit_date)

    return header

  def check_ruleset(self, nowarnings, repo_dir):
    modificador = ''
    if nowarnings:
      modificador = '-w '

    orden = 'find ' + repo_dir + ' -type f -name "*.yar" -exec yarac ' + modificador + ' {} /dev/null \;'
    args = shlex.split(orden)
    output,error = subprocess.Popen(args, stdout = subprocess.PIPE, stderr= subprocess.PIPE).communicate()

    salida = output + "\n" + error

    return salida


  def test_ruleset(self, nowarnings, repo_dir):
    modificador = ''
    if nowarnings:
      modificador = '-w '

    ruleset = []

    for root,dirs,files in os.walk(repo_dir):
      for i in files:
        if i.endswith('.yar') or i.endswith('.yara'):
          ruleset.append('include "' + os.path.join(root, i) + '"\n') 

    f = open(repo_dir + '/../fullruleset.yar', 'w')
    f.writelines(ruleset)
    f.close()

    orden = 'yara -x androguard=' + repo_dir + '/../androguard_report.json ' + repo_dir + '/../fullruleset.yar ' + repo_dir + '/../testfile'
    args = shlex.split(orden)
    output,error = subprocess.Popen(args, stdout = subprocess.PIPE, stderr= subprocess.PIPE).communicate()

    salida = output + "\n" + error

    return salida
    
  def check_syntax(self):
    repo_dir = self.script_path + '/rules' # os.path.dirname(os.path.realpath(__file__)) + '/rules'

    header = self.update_from_git(repo_dir)

    salida = self.check_ruleset(False, repo_dir)

    resultado = [header]
    aux = ''

    inicioln = len(repo_dir) + 1

    for i in salida.splitlines():
      linea = i[inicioln:]
      linea = string.replace(linea, "error", "<strong>error</strong>")
      #print "%d - %d" % (len(aux), len(linea))
      if len(aux) + len(linea) < 4096:
        aux = aux + '\n' + linea
      else:
        resultado.append(aux)
        aux = ''

    if aux != '':
      resultado.append(aux)

    resultado.append("Comprobación finalizada.")
    return resultado


  def check_syntax_nowarning(self):
    repo_dir = self.script_path  + '/rules' # os.path.dirname(os.path.realpath(__file__)) + '/rules'

    header = self.update_from_git(repo_dir)

    salida = self.check_ruleset(True, repo_dir)

    resultado = [header]
    aux = ''

    inicioln = len(repo_dir) + 1

    for i in salida.splitlines():
      if i == "":
        continue
      linea = i[inicioln:]
      procesada = re.match('(.*)\((\d*)\)\: (.*)', linea)
      fichero,linea_err,texto_err = procesada.groups()
      linea_err = int(linea_err)
      res_parcial = ''
      for j in xrange(linea_err-5, linea_err+5):
        aux2 = linecache.getline(repo_dir + '/' + fichero, j)
        if j == linea_err:
          aux2 = '<strong>' + aux2[:-1] + '</strong>\n'
        else:
          aux2 = '<pre>' + aux2[:-1] + '</pre>\n'
        res_parcial = res_parcial + aux2
      aux = 'Error encontrado en el fichero <strong>%s</strong> - Linea <strong>%d</strong>\nDescripción del error:\n<em>%s</em>\nContexto:\n%s' % (fichero, linea_err, texto_err, res_parcial)
      resultado.append(aux)
    resultado.append("Comprobación finalizada.")
    return resultado


  def ruleset_test(self):
    repo_dir = self.script_path + '/rules' # os.path.dirname(os.path.realpath(__file__)) + '/rules'

    header = self.update_from_git(repo_dir)

    salida = self.test_ruleset(False, repo_dir)

    resultado = [header]
    aux = ''

    inicioln = len(repo_dir) + 1

    for i in salida.splitlines():
      if i.find(repo_dir) < 0 or (i.find(repo_dir) >= 0 and i.find('testfile') >= 0):
        continue
      linea = i[inicioln:]
      linea = string.replace(linea, "error", "<strong>error</strong>")
      #print "%d - %d" % (len(aux), len(linea))
      if len(aux) + len(linea) < 4096:
        aux = aux + '\n' + linea
      else:
        resultado.append(aux)
        aux = ''

    if aux != '':
      resultado.append(aux)
    resultado.append("Comprobación finalizada.")
    return resultado

if __name__ == '__main__':
  yarabot = YaraBot(sys.argv)
  daemon_runner = runner.DaemonRunner(yarabot)
  daemon_runner.daemon_context.files_preserve=[yarabot.handler.stream]
  daemon_runner.do_action()
