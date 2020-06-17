def sortControlFlowGraph(n, sortedCFG):
  if type(n) is not list: # basement state
    return

  for i in range(0, len(n)): # recursive call
    node = [n[i][0:2], 1, 0] # node, numOfRules, stageNum
    sortedCFG.append(node)
    if n[i][0] != 'apply':
      if n[i][0] == 'else':
        sortControlFlowGraph(n[i][1], sortedCFG)  
      else: # 'if' or 'else if'
        sortControlFlowGraph(n[i][2], sortedCFG)

def calculateNumOfEntries(sortedCFG, rdic):
  for node in sortedCFG:
    if node[0][0] == 'apply':
      table = node[0][1]
      if table in rdic:
        node[1] += len(rdic[table])
  
virtualStages = [0, 100, 0, 0, 0, 0]
STAGE_SIZE = 100
def mapControlflowToStage(sortedCFG):
  # map to virtual stage
  i = 0
  for node in sortedCFG:
    while virtualStages[i] + node[1] > STAGE_SIZE: # if stage entries are full, skip
      i += 1
    virtualStages[i] += node[1] # stage usage update
    node[2] = i # node info update
    i += 1

def main():
  clist = []; tdic = {}; rdic = {}
  mapControlflowToStage(clist)

main()