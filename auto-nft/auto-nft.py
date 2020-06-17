import request_analyzer as ra
import resource_manager as rm
import rule_generator as rg

def main():
  clist = []; tdic = {}; rdic = {}; sortedCFG = []
  
  ra.parseP4Code('firewall.p4', tdic, clist)
  ra.parseP4Rules('firewall_rules', rdic)

  rm.sortControlFlowGraph(clist[0][2], sortedCFG)
  rm.calculateNumOfEntries(sortedCFG, rdic)
  rm.mapControlflowToStage(sortedCFG)

  rules = rg.getRuleTemplate('tofino')
  rlist = rg.translateRules(0, rules, sortedCFG, tdic, rdic)

if __name__ == '__main__':
  main()