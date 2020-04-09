from pyparsing import *
from pprint import pprint

def parseP4Code(filename, tdic, clist):
  with open('../p4/' + filename, 'r') as f:
    data = f.read()
  
  # define basic punctuation and data types 
  LBRACE,RBRACE,LPAREN,RPAREN,SEMI,COLON = map(Suppress,"{}();:") 
  string = Word(alphanums + '_.') 

  # parser
  
  # table
  TABLE = Keyword("table")
  READS = Keyword("reads")
  ACTIONS = Keyword("actions")

  match = Group(string("field") + COLON + string("method") + SEMI)
  action = string("name") + SEMI
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
      tdic[val[1]] = {'key' : val[2][1:], 'action' : val[3][1:]}
    elif val[0] == 'control':
      clist.append(val)

  print('table dictionary')
  for k, v in tdic.items():
    print('table name = ' + k)
    print('--- key list = ' + str(v['key']))
    print('--- action list = ' + str(v['action']))
    print

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


def parseP4Rules(filename, rdic):
  with open('../p4/' + filename, 'r') as f:
    rules = f.readlines()
    
    for rule in rules:
      rule = rule.split()
      rdic[rule[0]] = [rule[1], rule[2:]]
      print rule[0] , " : ", rdic[rule[0]]


def main():
  clist = []; tdic = {}; rdic = {}
  parseP4Code('firewall.p4', tdic, clist)
  parseP4Rules('firewall_rules', rdic)
  mapControlflowToStage(clist)

main()