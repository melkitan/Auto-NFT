from pyparsing import *
from pprint import pprint

def parseP4Code(filename, tlist, clist):
  with open(filename, 'r') as f:
    data = f.read()
  
  # define basic punctuation and data types 
  LBRACE,RBRACE,LPAREN,RPAREN,SEMI,COLON = map(Suppress,"{}();:") 
  string = Word(alphanums + '_.') 

  # table
  TABLE = Keyword("table")
  READS = Keyword("reads")
  ACTIONS = Keyword("actions")

  match = Group(string("field") + COLON + string("method") + SEMI)
  action = Group(string("name") + SEMI)
  reads = Group(READS + LBRACE + ZeroOrMore(match) + RBRACE)
  actions = Group(ACTIONS + LBRACE + ZeroOrMore(action) + RBRACE)

  table = Group(TABLE + string("name") + LBRACE + reads + actions + RBRACE)

  # control
  CONTROL = Keyword("control") 
  APPLY = Keyword("apply") 
  VALID = Keyword("valid")
  IF = Keyword("if")
  ELSEIF = Keyword("else if")
  ELSE = Keyword("else")


  # define structure expressions 
  apply_t = Group(APPLY + LPAREN + string("name") + RPAREN + SEMI)
  valid = Group(VALID + LPAREN + string("name") + RPAREN)

  ifstat = Forward()
  elseifstat = Forward()
  elsestat = Forward()
  ifstat << Group(IF + LPAREN + valid + RPAREN + LBRACE + Group(ZeroOrMore(ifstat | elseifstat | elsestat | apply_t))("block") + RBRACE)
  elseifstat << Group(ELSEIF + LPAREN + valid + RPAREN + LBRACE + Group(ZeroOrMore(ifstat | elseifstat | elsestat | apply_t))("block") + RBRACE)
  elsestat << Group(ELSE + LBRACE + Group(ZeroOrMore(ifstat | elseifstat | elsestat | apply_t))("block") + RBRACE)

  ctr = Group(CONTROL + string("name") + LBRACE + Group(ZeroOrMore(ifstat | apply_t))("block") + RBRACE)

  code = Group(ZeroOrMore(table | ctr))
  code.ignore(cStyleComment)

  # parse the sample text 
  result = code.parseString(data).asList()[0]

  for val in result:
    if val[0] == 'table':
      tlist.append(val)
    elif val[0] == 'control':
      clist.append(val)

sortedCFG = []
def sortControlFlowGraph(n):
  if type(n) is not list: # basement state
    return

  for i in range(0, len(n)): # recursive call
    node = [n[i][0:2], 1, 0] # node, numOfRules, stageNum
    sortedCFG.append(node)
    if n[i][0] != 'apply':
      if n[i][0] == 'else':
        sortControlFlowGraph(n[i][1])  
      else: # 'if' or 'else if'
        sortControlFlowGraph(n[i][2])
  
virtualStages = [0, 100, 0, 0, 0, 0, 0, 0]
STAGE_SIZE = 100
def mapControlflowToStage(clist):
  # CFG sorts by topological order
  sortControlFlowGraph(clist[0][2])

  # calculate needed entry

  # map to virtual stage
  i = 0
  for node in sortedCFG:
    while virtualStages[i] + node[1] > STAGE_SIZE: # if stage entries are full, skip
      i += 1
    virtualStages[i] += node[1] # stage usage update
    node[2] = i # node info update
    i += 1

  print('sorted control flow graph')
  for v in sortedCFG:
    print(v)


def parseP4Rules():
  pass

def main():
  clist = []; tlist = []
  parseP4Code('firewall.p4', tlist, clist)
  parseP4Rules()
  mapControlflowToStage(clist)

main()
