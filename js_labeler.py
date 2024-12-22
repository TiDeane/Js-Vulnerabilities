from typing import List, Dict
import json

# Associates identifiers with whether they are sources, sinks, or neither
# If they are a source or sink, 'vulns' holds what vulnerability they relate to
labels = {}

"""
sources: Dict[str, str] = {} # Key = source, Value = name of vulnerability
sinks: Dict[str, str] = {} # Key = sink, Value = name of vulnerability
sanitizers: Dict[str, str] = {} # Key = sanitizer, Value = name of vulnerability
is_implicit: Dict[str, str] = {} # Key = name of vulnerability, Value = "yes" or "no"

c -> source (vulnerabilidade A)

    tmp = {'sources': ['A'], 'sinks': []}
    labels['c'] = tmp

    saved_labels = labels[identifier['name']]
    saved_labels['sources']
    saved_labels['sinks']
"""


def main(vulnDict, root):
    global vuln_dict
    vuln_dict = vulnDict
    parseVulnerabilityDict(vuln_dict)
    print(labels)
    traverse(root)
    print(labels)
    with open(f"test_tree.json", "w") as outfile: 
        json.dump(labels, outfile, indent=2)
    print(root['vulns'])

def parseVulnerabilityDict(vulnDict: List):   # Adds vulnerability patterns to saved labels
    for pattern in vuln_dict:
        for source_id in pattern['sources']:
            if source_id in labels:
                labels[source_id]['sources'] += [pattern['vulnerability']]
            else:
                tmp = {'sources': [pattern['vulnerability']], 'sinks': [], 'vulns': []}
                labels[source_id] = tmp
        for sink_id in pattern['sinks']:
            if sink_id in labels:
                labels[sink_id]['sinks'] += [pattern['vulnerability']]
            else:
                tmp = {'sources': [], 'sinks': [pattern['vulnerability']], 'vulns': []}
                labels[sink_id] = tmp                                    


def match_pattern(identifier):
    
    id_sources = []
    id_sinks = []

    """
    if identifier in sources.keys():
        id_sources += sources[identifier]
    elif identifier in sinks.keys():
        id_sinks += sinks[identifier]
    """
    
    for pattern in vuln_dict:
        print("pattern sources: " + str(pattern['sources']))
        print("identifier: " + str(identifier))
        if (identifier in pattern['sources']):
            id_sources += pattern['vulnerability']
            #print(f"added {pattern['vulnerability']} to ")
        elif (identifier in pattern['sinks']):
            id_sinks += pattern['vulnerability']
    
    return id_sources, id_sinks
            
    
# Traverses every node in the AST
def traverse(node, left = True):
    #print("Inside traverse: " + str(node))
    if isinstance(node, dict):
        if node.get('type') == 'Program':
            label_program(node)
        elif node.get('type') == 'ExpressionStatement':
            label_expressionstmt(node)
        elif node.get('type') == 'AssignmentExpression':
            label_assignment(node)
        elif node.get('type') == 'Identifier' and left:
            label_identifier_left(node)
        elif node.get('type') == 'Identifier' and not left:
            label_identifier_right(node)
        elif node.get('type') == "CallExpression":
            label_call(node)
        elif node.get('type') == 'Literal':
            label_literal(node)
        else:
            print("Error: Unknown node type")

# Root node
def label_program(node):
    print("Labeling program")
    if isinstance(node, dict):
        node['vulns'] = []         
        for stmt in node['body']:
            traverse(stmt)
            node['vulns'] += stmt['vulns']   # Accumulates all found vulnerabilities

def label_expressionstmt(node):
    print("Labeling expressionstmt")
    if isinstance(node, dict):
        node['vulns'] = []
        node['sinks'] = []
        node['sources'] = []
        expression = node['expression']
        traverse(expression)
        node['vulns'] += expression['vulns']
        node['sources'] += expression['sources']   # Accumulates the vulnerabilites of the expression it states

def label_assignment(node):
    print("Labeling assignment")
    if isinstance(node, dict):
        node['vulns'] = []
        node['sinks'] = []
        node['sources'] = []
        left = node['left']
        right = node['right']
        traverse(left)
        traverse(right, False)
        node['vulns'] += right['vulns']      # Accumulates vulnerabilities of the right
        node['sources'] += left['sources'] + right['sources']
        node['sinks'] += left['sinks'] + right['sinks']
    
        explicit_vulnerabilities = list(set(left['sinks']).intersection(right['sources'])) # Detects explicit vulnerabilities if there are sinks in the left and sources in the right that match
        node['vulns'] += explicit_vulnerabilities
        labels[left['name']] = node
        
def label_identifier_left(node):
    if isinstance(node, dict):
        identifier = node['name']
        print("Labeling identifier (left) " + identifier)
        node['sources'], node['sinks'] = match_pattern(identifier)

def label_identifier_right(node):
    if isinstance(node, dict):
        saved_label = labels[node['name']]
        print("Labeling identifier (right) " + str(saved_label))
        node['vulns'] = saved_label['vulns']
        node['sources'] = saved_label['sources']
        node['sinks'] = saved_label['sinks']
        print(f"identifier label {node['name']}'s sources: {saved_label['sources']}")
        print(f"node {node['name']}'s sources: {node['sources']}")

def label_literal(node):
    print("Labeling literal")
    if isinstance(node, dict):
        node['sources'] = []
        node['sinks'] = []
        node['vulns'] = []

def label_call(node):
    print("Labeling call")
    if isinstance(node, dict):
        callee = node["callee"]
        node['vulns'] = []
        node['sources'] = []
        node['sinks'] = []
        print("callee = " + str(callee))
        traverse(callee, False)
        print("callee sources: " + str(callee['sources']))
        node['sources'] += callee['sources']   # Accumulates the vulnerabilites of the expression it states
        node['sinks'] += callee['sinks']

        explicit_vulnerabilities = []
        arguments = node["arguments"]

        for arg in arguments:
            traverse(arg, False)
            node['sources'] += arg['sources']
            node['sinks'] += arg['sinks']
            explicit_vulnerabilities += (set(callee['sinks']).intersection(arg['sources'])) # Detects explicit vulnerabilities if there are sinks in the callee and sources in the arguments that match
        node['vulns'] += explicit_vulnerabilities