import json
import os

def getRuleTemplate(target):
  with open('switchInfo/' + target + '/rule_form/rules.json', 'r') as f:
    loadedJson = json.load(f)
    rules = {}
    for obj in loadedJson:
      rules[obj['type']] = [obj['value'], obj['params']]
  return rules

actionMask = {'do_forward' : 0, 'drop' : 31, 'hash' : 15, 'mod_112_src' : 2, 'mod_112_dst' : 1}
def generateMatchRule(ruleTemplate, keys, matchFields, actionName):
  # mapping input and match fields of table
  kdic = {}
  for i in range(len(keys)):
    kdic[keys[i][0]] = matchFields[i]

  # ethernet
  eth_srcAddr, eth_srcAddr_mask = 'hdr.eth.srcAddr' in kdic and (int(kdic['hdr.eth.srcAddr']), 2 ** 48 - 1) or (0, 0)
  eth_dstAddr, eth_dstAddr_mask = 'hdr.eth.dstAddr' in kdic and (int(kdic['hdr.eth.dstAddr']), 2 ** 48 - 1) or (0, 0)
  eth_etherType, eth_etherType_mask = 'hdr.eth.etherType' in kdic and (int(kdic['hdr.eth.etherType']), 2 ** 16 - 1) or (0, 0)
  etherMatch = ruleTemplate[1]['eth'] % (eth_srcAddr, eth_dstAddr, eth_etherType)
  etherMatchMask = ruleTemplate[1]['eth'] % (eth_srcAddr_mask, eth_dstAddr_mask, eth_etherType_mask)
  # ipv4
  ipv4_protocol, ipv4_protocol_mask = 'hdr.ipv4.protocol' in kdic and (int(kdic['hdr.ipv4.protocol']), 2 ** 8 - 1) or (0, 0)
  ipv4_hdrChecksum, ipv4_hdrChecksum_mask = 'hdr.ipv4.hdrChecksum' in kdic and (int(kdic['hdr.ipv4.hdrChecksum']), 2 ** 16 - 1) or (0, 0)
  ipv4_srcAddr, ipv4_srcAddr_mask = 'hdr.ipv4.srcAddr' in kdic and (int(kdic['hdr.ipv4.srcAddr']), 2 ** 24 - 1) or (0, 0)
  ipv4_dstAddr, ipv4_dstAddr_mask =  'hdr.ipv4.dstAddr' in kdic and (int(kdic['hdr.ipv4.dstAddr']), 2 ** 24 - 1) or (0, 0)
  ipv4Match= ruleTemplate[1]['ipv4'] % (ipv4_protocol, ipv4_hdrChecksum, ipv4_srcAddr, ipv4_dstAddr)
  ipv4MatchMask= ruleTemplate[1]['ipv4'] % (ipv4_protocol_mask, ipv4_hdrChecksum_mask, ipv4_srcAddr_mask, ipv4_dstAddr_mask)
  # tcp
  tcp_srcPort, tcp_srcPort_mask = 'hdr.tcp.srcPort' in kdic and (int(kdic['hdr.tcp.srcPort']), 2 ** 16 - 1) or (0, 0)
  tcp_dstPort, tcp_dstPort_mask = 'hdr.tcp.dstPort' in kdic and (int(kdic['hdr.tcp.dstPort']), 2 ** 16 - 1) or (0, 0)
  tcpMatch = ruleTemplate[1]['tcp'] % (tcp_srcPort, tcp_dstPort)
  tcpMatchMask = ruleTemplate[1]['tcp'] % (tcp_srcPort_mask, tcp_dstPort_mask)

  # set action bitmap
  if actionName != None:
    actionBitmap = "0x%08X" % (1 << actionMask[actionName])
  else:
    actionBitmap = "0x00000000"
  return etherMatch + ", " + etherMatchMask + ", " + ipv4Match + ", " + ipv4MatchMask + ", " + tcpMatch + ", " + tcpMatchMask + ", " + actionBitmap

def generateActionRule():
  pass
  
def translateRules(inst_id, rules, sortedCFG, tdic, rdic):
  rlist = []
  # configuration rule (table_config_at_initial)
  # parameter (vdp_id, inst_id, stage_id, match_chain_bitmap, header_chain_bitmap)
  ruleTemplate = rules['cfg'][0]
  pipe = sortedCFG[0][2] < 3 and 'Ingress' or 'Egress'
  stage_id = sortedCFG[0][2] + 1 # virtual stage number of first node
  match_chain_bitmap = 4 # header match
  header_chain_bitmap = 1
  translateRules = ruleTemplate % (pipe, inst_id, inst_id, stage_id, match_chain_bitmap, header_chain_bitmap)
  rlist.append(translateRules)

  last_vs_num = -1
  for node in sortedCFG: # sortedCFG: [table_info, num_of_rules, virtual_stage_number]
    pipe = node[2] < 3 and 'Ingress' or 'Egress'
    virtual_stage_num = node[2] + 1

    # next stage rule (table_set_next_stage)
    if last_vs_num != -1:
      next_stage = rules['next_stage'][0] % (pipe, last_vs_num, inst_id, virtual_stage_num)
      rlist.append(next_stage)

    if node[0][0] == 'apply': # apply table, match and action
      actions = tdic[node[0][1]]['action']
      if node[0][1] not in rdic: continue
      for table_rule in rdic[node[0][1]]: # table_rule: [op, action name, match field, action param]
        # match
        headerMatchParam = generateMatchRule(rules['header_match'], tdic[node[0][1]]['key'], table_rule[2], table_rule[1])
        translatedRule = rules['header_match'][0].format(pipe = pipe, virtualStageNum = virtual_stage_num)
        rlist.append(translatedRule + "(" + str(inst_id) + ", " + headerMatchParam + ")")

        # action
        # if table_rule[1] in actions: # if action name of rule is valid
        ruleTemplate = rules[table_rule[1]][0]
        translatedRule = ruleTemplate % (pipe, virtual_stage_num)
        params = ''
        for param in rules[table_rule[1]][1]: # param: [param_name, parameter format]
          if param[0] == 'inst_id':
            params += (param[1][0] % inst_id)
          elif param[0] == 'hash_output':
            params += ", " + (param[1][0] % 0) + ", " + (param[1][1] % 0)
          else:
            for i in range(len(param[1])):
              params += ', ' + (param[1][i] % 0)

        translatedRule = translatedRule + '(' + params + ')'
        if translatedRule not in rlist:
          rlist.append(translatedRule)
    else: # if/else statements
      pass
    last_vs_num = virtual_stage_num

  return rlist

def makeFiles(rlist, target):
  f = open('tmp.py', 'w')

  head = open('switchInfo/' + target + '/rule_form/head', 'r')
  f.write(head.read())
  head.close()

  for v in rlist:
    f.write("    " + v + "\n")

  tail = open('switchInfo/' + target + '/rule_form/tail', 'r')
  f.write(tail.read())
  tail.close()

  f.close()
  return

def populateRules(target):
  cmd = open('switchInfo/' + target + "/command", 'r')
  os.system(cmd.read())