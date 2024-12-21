from js_analyser.py import vuln_dict
from typing import List, Dict

labels = {}

sources: Dict[str, str] = {} # Key = source, Value = name of vulnerability
sinks: Dict[str, str] = {} # Key = sink, Value = name of vulnerability
sanitizers: Dict[str, str] = {} # Key = sanitizer, Value = name of vulnerability
is_implicit: Dict[str, str] = {} # Key = name of vulnerability, Value = "yes" or "no"


def parseVulnerabilityDict(vulnDict: List, sources, sinks, sanitizers, is_implicit):
    """Constructs the sources, sinks, sanitizers, and is_implicit dictionaries"""
    
    for vulnerability in vulnDict:
        for sink in vulnerability["sinks"]:
            sinks[sink] = vulnerability["vulnerability"]
        for source in vulnerability["sources"]:
            sources[source] = vulnerability["vulnerability"]
        for sanitizer in vulnerability["sanitizers"]:
            sanitizers[sanitizer] = vulnerability["vulnerability"]
        is_implicit[vulnerability["vulnerability"]] = vulnerability["implicit"]


def match_pattern(patterns, identifier):
    
    id_sources = []
    id_sinks = []

    """
    if identifier in sources.keys():
        id_sources += sources[identifier]
    elif identifier in sinks.keys():
        id_sinks += sinks[identifier]
    """
    
    for pattern in patterns:
        if (identifier in pattern['sources']):
            id_sources += pattern['vulnerability']
        elif (identifier in pattern['sinks']):
            id_sinks += pattern['vulnerability']
    
    return id_sources, id_sinks
            
    
# Traverses every node in the AST
def traverse(node, left = True):
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
        else:
            print("wut")

# Root node
def label_program(node):
    if isinstance(node, dict):
        node['vulns'] = []         
        for stmt in node['body']:
            traverse(stmt)
            node['vulns'] += stmt['vulns']   # Accumulates all found vulnerabilities

def label_expressionstmt(node):
    if isinstance(node, dict):
        node['vulns'] = []
        node['sinks'] = None
        node['srcs'] = []
        expression = node['expression']
        traverse(expression)
        node['vulns'] += expression['vulns']
        node['srcs'] += expression['srcs']   # Accumulates the vulnerabilites of the expression it states

def label_assignment(node):
     if isinstance(node, dict):
        node['vulns'] = []
        node['sinks'] = None
        node['srcs'] = []
        left = node['left']
        right = node['right']
        traverse(left)
        traverse(right, False)     
        node['vulns'] += right['vulns']      # Accumulates vulnerabilities of the right
        node['srcs'] += left['srcs'] + right['srcs']
        node['sinks'] += left['sinks'] + right['sinks']
        explicit_vulnerabilities = list(set(left['sinks']).intersection(right['srcs'])) # Detects explicit vulnerabilities if there are sinks in the left and sources in the right that match
        node['vulns'] += explicit_vulnerabilities
        labels[left['name']] = node
        
def label_identifier_left(node):
    if isinstance(node, dict):
        identifier = node['name']
        node['srcs'], node['sinks'] = match_pattern(vuln_dict, identifier)

def label_identifier_right(node):
    if isinstance(node, dict):
        saved_label = labels[node['name']]
        node['vulns'] = saved_label['vulns']
        node['sources'] = saved_label['sources']
        node['sinks'] = saved_label[]
def label_literal(node):
    if isinstance(node, dict):
        node['srcs'] = []
        node['sinks'] = None

def label_call(node):
    if isinstance(node, dict):
        callee = node["callee"]
        node['vulns'] = []
        node['srcs'], node['sinks'] = match_pattern(vuln_dict, callee)
        traverse(callee)
        node['srcs'] += callee['srcs']   # Accumulates the vulnerabilites of the expression it states
        node['sinks'] += callee['sinks']

        arguments = node["arguments"]
        for arg in arguments:
            traverse(arg)
        