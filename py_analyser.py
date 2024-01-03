from _ast import BinOp, Constant
import sys
import ast
import json
from typing import Any
from astexport.export import export_json

# ---------------- GLOBAL DEFINITIONS ---------------------

vulnerabilities = {}
foundSources = []
detectedVulnerabilities = []
detectedVulnerabilitiesCheck = []
instantiatedVariables = []

# ---------------- AUXILIARY FUNCTIONS ---------------------

def returnFileAsString(filename):
    file = open(filename,"r")
    fileString = file.read()
    file.close()
    return fileString

def checkArguments():
    if len(sys.argv) != 3:
        print("Invalid amount of arguments, exiting program!")
        exit()

def createVulnerabilityDictionary(filename):
    f = open(filename)
    data = json.load(f)
    vuln = {}

    for i in data:
        vulnerabilityName = i["vulnerability"]
        vuln[vulnerabilityName] = {}
        vuln[vulnerabilityName]["sources"] = i["sources"]
        vuln[vulnerabilityName]["sanitizers"] = i["sources"]
        vuln[vulnerabilityName]["sinks"] = i["sinks"]
        vuln[vulnerabilityName]["implicit"] = i["implicit"]
        vuln[vulnerabilityName]["counter"] = 1
    
    return vuln

def listToFile(filenameWithPy, list):
    filenameWithoutPy = filenameWithPy.split("/")[1]
    filename = filenameWithoutPy.split(".")[0] + ".output.json"
    f = open("output/" + filename, "w+")
    f.write(json.dumps(list))
    f.close()

def printAST(ast):
    # Convert the AST to JSON using astexport
    json_ast = export_json(ast)
    parsed_json = json.loads(json_ast)
    pretty_json = json.dumps(parsed_json, indent=4)
    print(pretty_json)

def addSource(vulnName, srclineno, srcfunccall, varid):
    """adds a source to the existing list of sources foundSources"""
    d = {"vulnerability" : vulnName, "lineNo" : srclineno, "function" : srcfunccall, "variable" : varid}
    if d not in foundSources:
        foundSources.append(d)

def createVulnerability(vulnname, srcname, srclineno, sinkname, sinklineno, unsanitized, unsanitized_list):
    """creates a vulnerability and appends it to the list to be printed as an output"""
    vuln = {}
    vuln["source"] = [srcname, srclineno]
    vuln["sink"] = [sinkname, sinklineno]
    if unsanitized: vuln["unsanitized_flows"] = "yes"
    else: vuln["unsanitized_flows"] = "no"
    vuln["sanitized_flows"] = unsanitized_list

    if unsanitized: checkDict = {"vulnerability" : vulnname, "source" : [srcname, srclineno], "sink" : [sinkname, sinklineno], "unsanitized_flows": "yes" ,"sanitized_flows" : unsanitized_list}
    else: checkDict = {"vulnerability" : vulnname, "source" : [srcname, srclineno], "sink" : [sinkname, sinklineno], "unsanitized_flows": "no" ,"sanitized_flows" : unsanitized_list}
    
    #checks if vulnerability already exists, if it does does not add
    if checkDict not in detectedVulnerabilitiesCheck:
        detectedVulnerabilitiesCheck.append(checkDict)
        vuln["vulnerability"] = vulnname + "_" + str(vulnerabilities[vulnname]["counter"])
        vulnerabilities[vulnname]["counter"] += 1
        detectedVulnerabilities.append(vuln)

def checkVulnerabilityField(vuln, field):
    """returns vulnerability names if exists, None if else"""
    res = []
    for vulnerabilityName, vulnerability in vulnerabilities.items(): # check all vulnerabilities we are searching for
        if (vuln in vulnerability[field]):
            res.append(vulnerabilityName)
    if res == []: return None
    return res

def checkFoundSourcesField(vuln, field):
    """returns existing sources/flows if they exist, None if else"""
    res = []
    for src in foundSources:
        if vuln == src[field]:
            res.append(src)
    if res == []: return None
    return res

# ---------------- NODEVISITOR OVERRIDE CLASS ---------------------

class AstTraverser(ast.NodeVisitor):
    def __init__(self):
        self.count = 0
    
    def generic_visit(self, node):
        #print(type(node).__name__)
        ast.NodeVisitor.generic_visit(self, node)

    def visit_Assign(self, node):
        self.generic_visit(node)
    
    def visit_Expr(self, node):
        self.generic_visit(node)
    
    def visit_Name(self, node):
        self.generic_visit(node)
        #previous assignment in this LoC
        parent = getParentIfIsType(node,ast.Assign)
        if parent: #if there's an assignment before the call
            assignBeforeName(node,parent)
        
        #previous call in this LoC TODO
        parent = getParentIfIsType(node,ast.Call)
        if parent: #if there's an assignment before the call
            callBeforeName(node,parent)
        
        #instantiate variable if type store
        if isinstance(node.ctx, ast.Store):
            instantiatedVariables.append(node.id)

    
    def visit_BinOp(self, node):
        self.generic_visit(node)
    
    def visit_Call(self, node):
        self.generic_visit(node)
        #previous assignment in this LoC
        parent = getParentIfIsType(node,ast.Assign)
        if parent: #if there's an assignment before the call
            assignBeforeCall(node, parent)

        #previous Expression in this LoC
        parent = getParentIfIsType(node,ast.Expr)
        if parent: #if there's an expression before the call
            expressionBeforeCall(node, parent)

# ---------------- AST OPERATION FUNCTIONS ---------------------
            
def callBeforeName(node, parent):
    if isinstance(node.ctx, ast.Load): #check if name's context is of type load
        #check if any of the existing flows have a sink in the call

        vuln = checkVulnerabilityField(parent.func.id, "sinks")
        if vuln:
            for v in vuln:
                src = checkFoundSourcesField(node.id, "variable")#TODO maybe plus function
                if src:
                    for s in src:
                        createVulnerability(s["vulnerability"], s["function"], s["lineNo"],
                                        parent.func.id, parent.func.lineno, True, []) #TODO hard coded sanitisation
                
                if node.id not in instantiatedVariables and node.id !=parent.func.id: #uninstantiated variables count as sources
                    createVulnerability(v, node.id, node.lineno,
                                        parent.func.id, parent.func.lineno, True, []) #TODO hard coded sanitisation
        
        #check if node.id is different than parent(if parent is call), then add vuln
        
        
def assignBeforeName(node, parent):
    if isinstance(node.ctx, ast.Load): #check if name's context is of type load
        #create vulnerability with function as variable if vatiable is a defined source
        vuln = checkVulnerabilityField(node.id, "sources")
        if vuln:
            for v in vuln:
                addSource(v, node.lineno ,node.id, node.id) #potentially problematic if multiple assignnments, but no test has this
        #check if is vulnerable argument
        src = checkFoundSourcesField(node.id, "variable")
        if src:
            for s in src:
                addSource(s["vulnerability"], s["lineNo"] ,s["function"], parent.targets[0].id) #potentially problematic if multiple assignnments, but no test has this
                vuln = checkVulnerabilityField(parent.targets[0].id , "sinks") #if parent name is a sink
                if vuln:
                    for v in vuln:
                        createVulnerability(v, s["function"], s["lineNo"],
                                        parent.targets[0].id, parent.targets[0].lineno, True, []) #TODO hard coded sanitisation

    #might want to check if type store is overwritten by anything not tainted, if so should we remove flow?

def expressionBeforeCall(node, parent):
    """handles the case where there's an expression before a call"""
    vuln = checkVulnerabilityField(node.func.id, "sinks")
    if vuln: #if current call is a vulnerability
        for arg in node.args: #iterate through function arguments
            for i in range(0,len(foundSources)): #iterate through existing security violating flows
                if (arg.id in foundSources[i]["variable"]): #if there's a tainted argument in the sink
                    createVulnerability(foundSources[i]["vulnerability"], foundSources[i]["function"], foundSources[i]["lineNo"],
                                        node.func.id, node.func.lineno, True, []) #TODO hard coded sanitisation

def assignBeforeCall(node, parent):
    """handles the case where there's an assign before a call"""
    vuln = checkVulnerabilityField(node.func.id, "sources")
    if vuln: #if current call is a vulnerability
        for v in vuln:
            for target in parent.targets:
                addSource(v, node.func.lineno ,node.func.id, target.id)
                vuln = checkVulnerabilityField(target.id, "sinks")
                if vuln: #if the parent is a sink
                    for v in vuln:
                        createVulnerability(v, node.func.id, node.func.lineno,
                                        target.id, target.lineno, True, []) #TODO hard coded sanitisation
    
    
def getParentIfIsType(node, type):
    """returns parent any parent is of type type, None if else"""
    currentNode = node
    while hasattr(currentNode,"parent"):
        if isinstance(currentNode.parent,type):
            return currentNode.parent
        newNode = currentNode.parent
        currentNode = newNode
    return None

def createParents(astTree): #we can see parent node by calling node.parent
    """creates a parent object for each node in the tree, useful for traversing the tree from a different node"""
    for node in ast.walk(astTree):
        for child in ast.iter_child_nodes(node):
            child.parent = node

# ---------------- PROGRAM EXECUTION START ---------------------

checkArguments()

programFilename = sys.argv[1]
vulnerabilitiesFilename = sys.argv[2]

#ast tree of program
programAST = ast.parse(returnFileAsString(programFilename))

#printAST(programAST)

#dictionary containing information about vulnerabilities, example for 1a patterns
#{'A': {'sources': ['c'], 'sanitizers': ['c'], 'sinks': ['d', 'e'], 'implicit': 'no'}}
#added a field "counter" to make program output possible
vulnerabilities = createVulnerabilityDictionary(vulnerabilitiesFilename)

#list containing detected vulnerabilities
detectedVulnerabilities = []


#create parent for every node
createParents(programAST)

#find vulnerabilites and add them to list
#TODO our project will be this

nodevisitor = AstTraverser()
nodevisitor.visit(programAST)

print(foundSources)
#print(vulnerabilities)
print(instantiatedVariables)
#print(detectedVulnerabilitiesCheck)

#create file for output and print list
#works only if files are in slices directory or in another directory, maybe change later
listToFile(programFilename, detectedVulnerabilities)