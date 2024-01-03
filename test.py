# TBD
import os
import json

#list with index 0 being command, index 1 being output file and index 2 being expected output
"""executions = [["python py_analyser.py slices/1a-basic-flow.py slices/1a-basic-flow.patterns.json", "output/1a-basic-flow.output.json", "slices/1a-basic-flow.output.json"],
              ["python py_analyser.py slices/1b-basic-flow.py slices/1b-basic-flow.patterns.json", "output/1b-basic-flow.output.json", "slices/1b-basic-flow.output.json"],
              ["python py_analyser.py slices/2-expr-binary-ops.py slices/2-expr-binary-ops.patterns.json", "output/2-expr-binary-ops.output.json", "slices/2-expr-binary-ops.output.json"],
              ["python py_analyser.py slices/3a-expr-func-calls.py slices/3a-expr-func-calls.patterns.json", "output/3a-expr-func-calls.output.json", "slices/3a-expr-func-calls.output.json"],
              ["python py_analyser.py slices/3b-expr-func-calls.py slices/3b-expr-func-calls.patterns.json", "output/3b-expr-func-calls.output.json", "slices/3b-expr-func-calls.output.json"],
              ["python py_analyser.py slices/3c-expr-attributes.py slices/3c-expr-attributes.patterns.json", "output/3c-expr-attributes.output.json", "slices/3c-expr-attributes.output.json"],
              ["python py_analyser.py slices/4a-conds-branching.py slices/4a-conds-branching.patterns.json", "output/4a-conds-branching.output.json", "slices/4a-conds-branching.output.json"],
              ["python py_analyser.py slices/4b-conds-branching.py slices/4b-conds-branching.patterns.json", "output/4b-conds-branching.output.json", "slices/4b-conds-branching.output.json"],
              ["python py_analyser.py slices/5a-loops-unfolding.py slices/5a-loops-unfolding.patterns.json", "output/5a-loops-unfolding.output.json", "slices/5a-loops-unfolding.output.json"],
              ["python py_analyser.py slices/5b-loops-unfolding.py slices/5b-loops-unfolding.patterns.json", "output/5b-loops-unfolding.output.json", "slices/5b-loops-unfolding.output.json"],
              ["python py_analyser.py slices/5c-loops-unfolding.py slices/5c-loops-unfolding.patterns.json", "output/5c-loops-unfolding.output.json", "slices/5c-loops-unfolding.output.json"],
              ["python py_analyser.py slices/6a-sanitization.py slices/6a-sanitization.patterns.json", "output/6a-sanitization.output.json", "slices/6a-sanitization.output.json"],
              ["python py_analyser.py slices/6b-sanitization.py slices/6b-sanitization.patterns.json", "output/6b-sanitization.output.json", "slices/6b-sanitization.output.json"],
              ["python py_analyser.py slices/7-conds-implicit.py slices/7-conds-implicit.patterns.json", "output/7-conds-implicit.output.json", "slices/7-conds-implicit.output.json"],
              ["python py_analyser.py slices/8-loops-implicit.py slices/8-loops-implicit.patterns.json", "output/8-loops-implicit.output.json", "slices/8-loops-implicit.output.json"]
              ]"""

executions = [["python py_analyser.py slices/1a-basic-flow.py slices/1a-basic-flow.patterns.json", "output/1a-basic-flow.output.json", "slices/1a-basic-flow.output.json"],
              ["python py_analyser.py slices/1b-basic-flow.py slices/1b-basic-flow.patterns.json", "output/1b-basic-flow.output.json", "slices/1b-basic-flow.output.json"],
              ["python py_analyser.py slices/2-expr-binary-ops.py slices/2-expr-binary-ops.patterns.json", "output/2-expr-binary-ops.output.json", "slices/2-expr-binary-ops.output.json"]]

for execution in executions:
    os.system(execution[0])
    fileOutput = open(execution[1])
    fileExpected = open(execution[2])
    stringOutput = json.load(fileOutput)
    stringExpected = json.load(fileExpected)
    output = json.dumps(stringOutput, sort_keys=True, indent = 1)
    expected = json.dumps(stringExpected, sort_keys=True, indent = 1)
    if (output == expected):
        print("file " + execution[1] + " has expected output!")
    else:
        print("file " + execution[1] + " has different output than expected!")
        print("actual output: " + execution[1] + ":")
        print(output)
        print("expected output: " + execution[2] + ":")
        print(expected)