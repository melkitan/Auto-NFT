class Target:
  def __init__(self, name):
    self.name = name
    self.nflist = []
    
  def addNf(nf):
    nflist.append(nf)

  def getNf():
    return self.nflist

  def translateRules(reqop, vals):
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