import json

def getRuleTemplate(target):
  with open('switchInfo/' + target + '/rule_form/rules.json', 'r') as f:
    loadedJson = json.load(f)
    rules = {}
    for obj in loadedJson:
      rules[obj['type']] = [obj['value'], obj['params']]
  return rules

def generateMatchRule(ruleTemplate, keys, matchFields, actionName):
  # mapping input and match fields of table
  kdic = {}
  for i in range(len(keys)):
    kdic[keys[i][0]] = matchFields[i]
  print kdic

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
  actionBitmap = "0x%08X" % 0
  return etherMatch + ", " + etherMatchMask + ", " + ipv4Match + ", " + ipv4MatchMask + ", " + tcpMatch + ", " + tcpMatchMask + ", " + actionBitmap

def translateRules(inst_id, rules, sortedCFG, tdic, rdic):
  rlist = []
  # configuration rule (table_config_at_initial)
  # rlist.append(configuration rule)
  
  for node in sortedCFG: # sortedCFG: [table_info, num_of_rules, virtual_stage_number]
    pipe = node[2] < 3 and 'Ingress' or 'Egress'
    virtualStageNum = node[2] % 3
    if node[0][0] == 'apply': # apply table, match and action
      actions = tdic[node[0][1]]['action']
      if node[0][1] not in rdic: continue
      for table_rule in rdic[node[0][1]]: # table_rule: [op, action name, match field, action param]
        # match
        headerMatchParam = generateMatchRule(rules['header_match'], tdic[node[0][1]]['key'], table_rule[2], table_rule[1])
        translatedRule = rules['header_match'][0].format(pipe = pipe, virtualStageNum = virtualStageNum)
        rlist.append(translatedRule + "(" + str(inst_id) + ", " + headerMatchParam + ")")

        # action
        if table_rule[1] in actions: # if action name of rule is valid
          ruleTemplate = rules[table_rule[1]][0]
          translatedRule = ruleTemplate.format(pipe = pipe, virtualStageNum = virtualStageNum)
          params = ''
          for param in rules[table_rule[1]][1]: # param: [param_name, parameter format]
            if param[0] == 'inst_id':
              params += (param[1][0] % inst_id)
            elif param[0] == 'action_param':
              for action_param_idx in range(len(table_rule[3])): # need to check hex type parameter
                params += ', ' + (param[1][action_param_idx] % int(table_rule[3][action_param_idx]))
            else: # exception
              for i in range(len(param[1])):
                params += ', ' + (param[1][i] % 0)
          translatedRule = translatedRule + '(' + params + ')'
          if translatedRule not in rlist:
            rlist.append(translatedRule)
    else: # condition statement (if/else), just match
      print "if: ", node[0][1]

  print "\n\n -- translated rule list -- "
  for v in rlist:
    print v
  return rlist

def makeFiles():
  # import rule template
  # make new p4 ruleset
  # make P4 ruleset file
  global pcnt

  f1 = open('switchInfo/' + self.name + '/rule_form/' + vals[0], 'r')
  f2 = open('tmp', 'w')

  forms = []
  for line in f1:
    forms.append(line)  
    insnum = -1

  output = ''
  cfg = ''; dstMAC = ''; fwdport = ''; dstIP = ''
  tgtIP = ''; srcIP = ''; dstport = ''; opcode = ''
  # l2fwd [dstMAC] [fwdport]
  if vals[0] == 'l2fwd':
    insnum = 0
    if reqop == 'insert':
      if 'cfg' not in l2fwd:
        cfg += forms[1]  
        cfg += forms[2]  
        l2fwd['cfg'] = [cfg, pcnt]
        resourceStatus['L2 Forwarding'][pcnt] += 2 
      if 'dstMAC' + vals[1] not in l2fwd:
        macnum = vals[1].split(':')
        rule = forms[4] % (seqnum[insnum], int(macnum[0], 16), int(macnum[1], 16), int(macnum[2], 16), int(macnum[3], 16), int(macnum[4], 16), int(macnum[5], 16))
        dstMAC += rule
        rule = forms[0] % (int(macnum[0], 16), int(macnum[1], 16), int(macnum[2], 16), int(macnum[3], 16), int(macnum[4], 16), int(macnum[5], 16), seqnum[insnum])
        dstMAC += rule
        l2fwd['dstMAC' + vals[1]] = [dstMAC, pcnt]
        resourceStatus['L2 Forwarding'][pcnt] += 2 
      if 'fwdport' + vals[2] not in l2fwd:
        rule = forms[3] % (seqnum[insnum], int(vals[2]))
        fwdport += rule
        l2fwd['fwdport' + vals[2]] = [fwdport, pcnt]
        resourceStatus['L2 Forwarding'][pcnt] += 1 
    else: # reqop == 'delete'
      if 'dstMAC' + vals[1] in l2fwd:
        resourceStatus['L2 Forwarding'][l2fwd['dstMAC' + vals[1]][1]] -= 2 
        del l2fwd['dstMAC' + vals[1]]
      if 'fwdport' + vals[2] in l2fwd:
        resourceStatus['L2 Forwarding'][l2fwd['fwdport' + vals[2]][1]] -= 1 
        del l2fwd['fwdport' + vals[2]]
      if len(l2fwd) == 1: # if all of the rules deleted
        resourceStatus['L2 Forwarding'][l2fwd['cfg'][1]] -= 2 
        del l2fwd['cfg']

  # l3fwd [dstIP] [fwdport]
  elif vals[0] == 'l3fwd':
    insnum = 1
    if 'cfg' not in l3fwd:
      cfg += forms[0]  
      cfg += forms[1]  
      cfg += forms[2]  
      l3fwd['cfg'] = cfg
      resourceStatus['L3 Forwarding'][pcnt] += 3
    if 'dstIP' + vals[1] not in l3fwd: 
      ipnum = vals[1].split('.')
      rule = forms[3] % (int(ipnum[0]), int(ipnum[1]), int(ipnum[2]), int(ipnum[3]), seqnum[insnum])
      dstIP += rule
      l3fwd['dstIP' + vals[1]] = dstIP
      resourceStatus['L3 Forwarding'][pcnt] += 1
    if 'fwdport' + vals[2] not in l3fwd:
      rule = forms[4] % (seqnum[insnum], int(vals[2]))
      fwdport += rule
      l3fwd['fwdport' + vals[2]] = fwdport
      resourceStatus['L3 Forwarding'][pcnt] += 1

  # fw [op] [srcIP] [dstport] [fwdport]
  elif vals[0] == 'fw':
    insnum = 2
    if 'cfg' not in fw:
      cfg += forms[0]  
      cfg += forms[1]  
      fw['cfg'] = cfg
      resourceStatus['Firewall'][pcnt] += 2
    if vals[1] == 'drop':
      if vals[1] + 'cfg' not in fw:
        cfg += forms[2]
        fw[vals[1] + 'cfg'] = forms[2]
        resourceStatus['Firewall'][pcnt] += 1
      if vals[2] != 'N' and 'srcIP' + vals[2] not in fw:
        ipnum = vals[2].split('.')
        rule = forms[4] % (int(ipnum[0]), int(ipnum[1]), int(ipnum[2]), int(ipnum[3]), seqnum[insnum])
        srcIP += rule
        fw['srcIP' + vals[2]] = srcIP
        resourceStatus['Firewall'][pcnt] += 1
      if vals[3] != 'N' and 'dstport' + vals[3] not in fw:
        rule = forms[6] % (int(vals[3]), seqnum[insnum])
        dstport += rule
        fw['dstport' + vals[3]] = dstport
        resourceStatus['Firewall'][pcnt] += 1

    elif vals[1] == 'fwd':
      if vals[2] != 'N' and 'srcIP' + vals[2] not in fw:
        ipnum = vals[2].split('.')
        rule = forms[3] % (int(ipnum[0]), int(ipnum[1]), int(ipnum[2]), int(ipnum[3]), seqnum[insnum])
        srcIP += rule
        fw['srcIP' + vals[2]] = srcIP
        resourceStatus['Firewall'][pcnt] += 1
      if vals[3] != 'N' and 'dstport' + vals[3] not in fw:
        rule = forms[5] % (int(vals[3]), seqnum[insnum])
        dstport += rule
        fw['dstport' + vals[3]] = dstport
        resourceStatus['Firewall'][pcnt] += 1
      if vals[4] != 'N' and 'fwdport' + vals[4] not in fw:
        rule = forms[7] % (seqnum[insnum], int(vals[4]))
        fwdport += rule
        fw['fwdport' + vals[4]] = fwdport
        resourceStatus['Firewall'][pcnt] += 1

  # arp [opcode] [tgtIP] [dstMAC]
  elif vals[0] == 'arp':
    insnum = 3
    if 'cfg' not in arp:
      cfg += forms[1]
      cfg += forms[2]  
      cfg += forms[3]  
      cfg += forms[4]  
      cfg += forms[6]  
      cfg += forms[8]  
      arp['cfg'] = cfg
      resourceStatus['ARP Proxy'][pcnt] += 6
    if 'op' + vals[1] not in arp:
      rule = forms[0] % (int(vals[1]), seqnum[insnum])
      opcode += rule
      arp['op' + vals[1]] = opcode
      resourceStatus['ARP Proxy'][pcnt] += 1
    if 'ip' + vals[2] + 'mac' + vals[3] not in arp:
      # tgtIP
      ipnum = vals[2].split('.')
      rule = forms[7] % (int(ipnum[0]), int(ipnum[1]), int(ipnum[2]), int(ipnum[3]))
      tgtIP += rule
      # dstMAC
      macnum = vals[3].split(':')
      rule = forms[5] % (int(macnum[0], 16), int(macnum[1], 16), int(macnum[2], 16), int(macnum[3], 16), int(macnum[4], 16), int(macnum[5], 16))
      dstMAC += rule
      arp['ip' + vals[2] + 'mac' + vals[3]] = tgtIP + dstMAC
      resourceStatus['ARP Proxy'][pcnt] += 2

  ruleset = cfg + opcode + dstMAC + srcIP + tgtIP + dstIP + fwdport + dstport
  f2.write(ruleset)

  if reqop == 'insert' and ruleset != '': 
    seqnum[insnum] += 1
    pcnt = (pcnt + 1) % 4

  f2.close()
  f1.close()
  return

# rules = getRuleTemplate("tofino")
# print rules