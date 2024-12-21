import esprima
import sys
import json
from typing import Dict, List

global vuln_dict

# Read code strip
with open(sys.argv[1], 'r') as f:
    program = f.read().strip()

ast = esprima.parseScript(program, loc = True)

ast_dict = esprima.parseScript(program, loc = True).toDict()

# Read vulnerabilities
with open(sys.argv[2], 'r') as file:
    vuln_dict = json.load(file)

print(vuln_dict)

# Save dict to json
with open(f"{sys.argv[1]}_tree.json", "w") as outfile: 
    json.dump(ast_dict, outfile, indent=2)
