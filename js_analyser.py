import esprima
import sys
import json
from typing import Dict, List
from js_labeler import main
import difflib

def diff_files(file1_path, file2_path):
    # Read the contents of both files
    with open(file1_path, 'r') as file1, open(file2_path, 'r') as file2:
        file1_lines = file1.readlines()
        file2_lines = file2.readlines()

    # Create a unified diff
    diff = difflib.unified_diff(
        file1_lines, file2_lines,
        fromfile=file1_path,
        tofile=file2_path,
        lineterm=''
    )

    # Print the differences line by line
    for line in diff:
        print(line)

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

main(vuln_dict, ast_dict)

#diff_files(f"./output{sys.argv[1][8:-3]}.output.json", "test_tree.json")
