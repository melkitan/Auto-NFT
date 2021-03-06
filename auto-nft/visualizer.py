import curses
from curses.textpad import Textbox, rectangle
import time
import os

padding = 2
MAX_RESOURCE_NUM = 50
NUM_OF_VS = 6
BAR_SIZE = 50
ratio = BAR_SIZE / MAX_RESOURCE_NUM
resourceNum = 0
resourceStatus = {} # nfname : vsResourcePerNF
pcnt = 0
seqnum = [0, 0, 0, 0]
vsResource = [0, 0, 0, 0, 0, 0] # all resource status per virtual stage
nfList = {} # control flow of NF

def mapControlflowToStage(clist, nfName):
  # CFG sorts by topological order
  # sortControlFlowGraph(clist[0][2])

  # calculate needed entry

  # map to virtual stage
  i = 0
  for node in clist:
    while vsResource[i] + node > MAX_RESOURCE_NUM: i = (i + 1) % 6 # if stage entries are full, skip
    vsResource[i] += node # stage usage update
    resourceStatus[nfName][i] = node
    i = (i + 1) % 6

def printResourceBar(screen, resourceInfo, vsLen):
  # stageN : 
  for i in range(0, vsLen):
    screen.addstr(padding + 2 + i, padding + 0, 'VirtualStage' + str(i + 1) + ' : ')

  reqPos = 0 
  cnt = [0 for _ in range(vsLen)]
  # for reqName, resource in resourceStatus.items():
    # # instance name
    # req_id = resource[len(resource) - 1]
    # print(req_id)
    # screen.addstr(padding + 1, padding + reqPos, reqName, curses.color_pair(req_id))
    # reqPos += len(reqName) + 2

  # resource of instance
  for nf in resourceInfo: 
    # if idx == vsLen: break
    for i in range(vsLen):
      for j in range(cnt[i], cnt[i] + nf[i]):
        screen.addstr(padding + i + 2, padding + j + 16, '#', curses.color_pair(1))
    cnt[i] = cnt[i] + nf[i]

  # # each percent of resource 
  # for i in range(vsLen):
  #   for j in range(cnt[i], BAR_SIZE):
  #     screen.addstr(padding + i + 2, padding + j + 16, '#')
  #   screen.addstr(padding + 2 + i, padding + BAR_SIZE + 18, '(' + str(cnt[i] * 100 / MAX_RESOURCE_NUM) + '%/100%)')

def main(screen):
  NFcnt = 0
  while True:
    screen.clear()

    # command help
    screen.addstr(padding + 14, padding + 0, '* Commands')
    screen.addstr(padding + 15, padding + 0, 'Ctrl-G or Enter : send request / Ctrl-C : exit')

    # current resource usage
    screen.addstr(padding + 0, padding + 0, '* Current resource usage of P4 Hypervisor')
    printResourceBar(screen)

    # input request
    screen.addstr(padding + 9, padding + 0, '* Enter the request ')
    edit_win = curses.newwin(1, BAR_SIZE, 11 + padding, 1 + padding)
    rectangle(screen, padding + 10, padding + 0, padding + 1 + 10 + 1, padding + 1 + BAR_SIZE + 1)
    screen.refresh()
    box = Textbox(edit_win)
    box.edit()
    input_text = box.gather()

    if input_text != '':
      resourceStatus['load_balancing'] = [0, 0, 0, 0, 0, 0, 4]
      nfList['load_balancing'] = [1, 11, 11, 18, 9, 9]
      mapControlflowToStage(nfList['load_balancing'], 'load_balancing')
      resourceStatus['firewall'] = [0, 0, 0, 0, 0, 0, 3]
      nfList['firewall'] = [10, 10, 1, 10, 10, 16]
      mapControlflowToStage(nfList['firewall'], 'firewall')
      resourceStatus['l3_forwarding'] = [0, 0, 0, 0, 0, 0, 2]
      nfList['l3_forwarding'] = [4, 3, 3, 3, 3, 3]
      mapControlflowToStage(nfList['l3_forwarding'], 'l3_forwarding')
      resourceStatus['l2_switching'] = [0, 0, 0, 0, 0, 0, 1]
      nfList['l2_switching'] = [3, 3, 3, 3, 3, 3]
      mapControlflowToStage(nfList['l2_switching'], 'l2_switching')

# init
def init():
  curses.initscr()

  curses.start_color()
  curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)
  curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_YELLOW)
  curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_GREEN)
  curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_MAGENTA)
  curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_CYAN)

  curses.wrapper(main)

if __name__ == '__main__':
  init()