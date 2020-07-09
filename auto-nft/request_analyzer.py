from pyparsing import *
from pprint import pprint

def parseP4Code(filename, tdic, clist):
  with open('../p4/' + filename, 'r') as f:
    data = f.read()
  
  # define basic punctuation and data types 
  LBRACE,RBRACE,LPAREN,RPAREN,SEMI,COLON,EQUAL = map(Suppress,"{}();:=") 
  string = Word(alphanums + '_.') 
  
  # table
  TABLE = Keyword("table")
  MATCHKEY = Keyword("key")
  ACTIONS = Keyword("actions")

  match = Group(string("field") + COLON + string("method") + SEMI)
  action = string("name") + SEMI
  matchkey = Group(MATCHKEY + EQUAL + LBRACE + ZeroOrMore(match) + RBRACE)
  actions = Group(ACTIONS + EQUAL + LBRACE + ZeroOrMore(action) + RBRACE)

  table = Group(TABLE + string("name") + LBRACE + matchkey + actions + RBRACE)

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

  ctr = Group(CONTROL + string("name") + LBRACE + Group(ZeroOrMore(ifstat | elseifstat | elsestat | apply_t))("block") + RBRACE)

  code = Group(ZeroOrMore(table | ctr))
  code.ignore(cStyleComment)

  # parse the sample text 
  result = code.parseString(data).asList()[0]
  
  for val in result:
    if val[0] == 'table':
      tdic[val[1]] = {'key' : val[2][1:], 'action' : val[3][1:]}
    elif val[0] == 'control':
      clist.append(val)

  # print('table dictionary')
  # for k, v in tdic.items():
  #   print('table name = ' + k)
  #   print('--- key list = ' + str(v['key']))
  #   print('--- action list = ' + str(v['action']))
  #   print

def parseP4Rules(filename, rdic):
  with open('../p4/' + filename, 'r') as f:
    rules = f.readlines()
    
    for rule in rules:
      rule = rule.split()
      if rule[0] in rdic:
        rdic[rule[0]].append([rule[1], rule[2]])
      else:  
        rdic[rule[0]] = [[rule[1], rule[2]]]
      delimIdx = rule.index("=>")
      rdic[rule[0]][len(rdic[rule[0]]) - 1].append(rule[3:delimIdx])
      rdic[rule[0]][len(rdic[rule[0]]) - 1].append(rule[delimIdx + 1:])