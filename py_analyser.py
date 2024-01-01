from _ast import Constant
import sys
import ast
import json
from typing import Any
from astexport.export import export_json

# ---------------- GLOBAL DEFINITIONS ---------------------

vulnerabilities = {}
foundSources = []
detectedVulnerabilities = []

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
    foundSources.append({"vulnerability" : vulnName, "lineNo" : srclineno, "function" : srcfunccall, "variable" : varid})

def createVulnerability(vulnname, srcname, srclineno, sinkname, sinklineno, unsanitized, unsanitized_list):
    vuln = {}
    vuln["vulnerability"] = vulnname + "_" + str(vulnerabilities[vulnname]["counter"])
    vulnerabilities[vulnname]["counter"] += 1
    vuln["source"] = [srcname, srclineno]
    vuln["sink"] = [sinkname, sinklineno]
    if unsanitized: vuln["unsanitized_flows"] = "yes"
    else: vuln["unsanitized_flows"] = "no"
    vuln["sanitized_flows"] = unsanitized_list

    detectedVulnerabilities.append(vuln)

def createParents(astTree): #we can see parent node by calling node.parent
    for node in ast.walk(astTree):
        for child in ast.iter_child_nodes(node):
            child.parent = node


# ---------------- AST OPERATION FUNCTIONS ---------------------

class AstTraverser(ast.NodeVisitor):
    def __init__(self):
        self.count = 0
    
    def generic_visit(self, node):
        ast.NodeVisitor.generic_visit(self, node)

    def visit_Assign(self, node):
        if (isinstance(node.value, ast.Call)): #there's a call to a function
            for vulnerabilityName, vulnerability in vulnerabilities.items(): # check all vulnerabilities we are searching for
                if (node.value.func.id in vulnerability["sources"]): # check if call is a source
                    addSource(vulnerabilityName, node.value.func.lineno ,node.value.func.id, node.targets[0].id)
        self.generic_visit(node)
    
    def visit_Expr(self, node):
        if (isinstance(node.value, ast.Call)): #check if node's value is a call
            for vulnerabilityName, vulnerability in vulnerabilities.items(): #iterate through existing vulnerabilities
                if (node.value.func.id in vulnerability["sinks"]): #check if function is a sink
                    if (node.value.args != []): #check if arguments exist
                        for arg in node.value.args: #iterate through arguments
                            for i in range(0,len(foundSources)): #iterate through existing flows
                                if (arg.id in foundSources[i]["variable"]): #check if argument(s) tainted
                                    #found tainted argument in sink
                                    createVulnerability(foundSources[i]["vulnerability"], foundSources[i]["function"], foundSources[i]["lineNo"],
                                                        node.value.func.id, node.value.func.lineno, True, []) #TODO hard coded sanitisation
                                    #TODO unsanitized flows
        self.generic_visit(node)
    
    def visit_Name(self, node):
        self.generic_visit(node)
    
    def visit_Call(self, node):
        self.generic_visit(node)
    

# ---------------- PROGRAM EXECUTION START ---------------------

checkArguments()

programFilename = sys.argv[1]
vulnerabilitiesFilename = sys.argv[2]

#ast tree of program
programAST = ast.parse(returnFileAsString(programFilename))

printAST(programAST)

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

#create file for output and print list
#works only if files are in slices directory or in another directory, maybe change later
listToFile(programFilename, detectedVulnerabilities)