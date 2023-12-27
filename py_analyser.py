import sys
import ast
import json
from astexport.export import export_json

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
    
    return vuln

def listToFile(filenameWithPy, list):
    filenameWithoutPy = filenameWithPy.split("/")[1]
    filename = filenameWithoutPy.split(".")[0] + ".output.json"
    f = open("output/" + filename, "w+")
    f.write(str(list))
    f.close()


# ---------------- PROGRAM EXECUTION START ---------------------

checkArguments()

programFilename = sys.argv[1]
vulnerabilitiesFilename = sys.argv[2]

#ast tree of program
programAST = ast.parse(returnFileAsString(programFilename))

# Convert the AST to JSON using astexport
json_ast = export_json(programAST)
parsed_json = json.loads(json_ast)
pretty_json = json.dumps(parsed_json, indent=4)  # Use indent parameter for indentation
print(pretty_json)


#dictionary containing information about vulnerabilities, example for 1a patterns
#{'A': {'sources': ['c'], 'sanitizers': ['c'], 'sinks': ['d', 'e'], 'implicit': 'no'}}
vulnerabilities = createVulnerabilityDictionary(vulnerabilitiesFilename)

#list containing detected vulnerabilities
detectedVulnerabilities = []

#find vulnerabilites and add them to list
#TODO our project will be this

#create file for output and print list
#works only if files are in slices directory or in another directory, maybe change later
listToFile(programFilename, detectedVulnerabilities)