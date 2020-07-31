import curses
from curses.textpad import Textbox, rectangle

import request_analyzer as ra
import resource_manager as rm
import rule_generator as rg
import visualizer as vsl

padding = 2
MAX_RESOURCE_NUM = 50
NUM_OF_VS = 6
BAR_SIZE = 50

def main():
  clist = []; tdic = {}; rdic = {}; sortedCFG = []
  
  ra.parseP4Code('firewall.p4', tdic, clist)
  ra.parseP4Rules('firewall_rules', rdic)

  rm.sortControlFlowGraph(clist[0][2], sortedCFG)
  rm.calculateNumOfEntries(sortedCFG, rdic)
  rm.mapControlflowToStage(sortedCFG)
  resourceInfo, vsLen = rm.resourcePerStage(sortedCFG)

  rules = rg.getRuleTemplate('tofino')
  rlist = rg.translateRules(0, rules, sortedCFG, tdic, rdic)
  rg.makeFiles(rlist, 'tofino')
  # rg.populateRules('tofino')

  return resourceInfo, vsLen

def gui(screen):
  NFcnt = 0
  resourceInfo = []
  while True:
    screen.clear()

    # command help
    screen.addstr(padding + 14, padding + 0, '* Commands')
    screen.addstr(padding + 15, padding + 0, 'Ctrl-G or Enter : send request / Ctrl-C : exit')

    # current resource usage
    screen.addstr(padding + 0, padding + 0, '* Current resource usage of P4 Hypervisor')
    vsl.printResourceBar(screen, resourceInfo, 6)

    # input request
    screen.addstr(padding + 9, padding + 0, '* Enter the request ')
    edit_win = curses.newwin(1, BAR_SIZE, 11 + padding, 1 + padding)
    rectangle(screen, padding + 10, padding + 0, padding + 1 + 10 + 1, padding + 1 + BAR_SIZE + 1)
    screen.refresh()
    box = Textbox(edit_win)
    box.edit()
    input_text = box.gather()

    if input_text != '':
      # resourceStatus['load_balancing'] = [0, 0, 0, 0, 0, 0, 4]
      # nfList['load_balancing'] = [1, 11, 11, 18, 9, 9]
      # mapControlflowToStage(nfList['load_balancing'], 'load_balancing')
      # resourceStatus['firewall'] = [0, 0, 0, 0, 0, 0, 3]
      # nfList['firewall'] = [10, 10, 1, 10, 10, 16]
      # mapControlflowToStage(nfList['firewall'], 'firewall')
      # resourceStatus['l3_forwarding'] = [0, 0, 0, 0, 0, 0, 2]
      # nfList['l3_forwarding'] = [4, 3, 3, 3, 3, 3]
      # mapControlflowToStage(nfList['l3_forwarding'], 'l3_forwarding')
      # resourceStatus['l2_switching'] = [0, 0, 0, 0, 0, 0, 1]
      # nfList['l2_switching'] = [3, 3, 3, 3, 3, 3]
      # mapControlflowToStage(nfList['l2_switching'], 'l2_switching')
      resourceInfo, vsLen = main()
      print resourceInfo
      vsl.printResourceBar(screen, resourceInfo, vsLen)


# init
def init():
  curses.initscr()

  curses.start_color()
  curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)
  curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_YELLOW)
  curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_GREEN)
  curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_MAGENTA)
  curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_CYAN)

  curses.wrapper(gui)

if __name__ == '__main__':
  init()  

# if __name__ == '__main__':
#   resourceInfo, vsLen = main()
#   print resourceInfo, ", ", vsLen