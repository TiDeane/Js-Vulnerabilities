from __future__ import annotations
from typing import List, Dict
import json
import copy

sequentialIds = {} # Dict of vulnerabilities to their number of occurences
sanitizers = [] # List of (sanitizer, vuln, source) tuples
found_vulns = [] # List of (vuln, source, source_line, sink, sink_line) tuples

def getSequentialId(vuln):
    if vuln in sequentialIds:
        sequentialIds[vuln] += 1
    else:
        sequentialIds[vuln] = 1
    
    return vuln + "_" + str(sequentialIds[vuln])

def matchSanitizers():
    for pattern in vuln_dict:
        for sanitizer in pattern['sanitizers']:
            for source in pattern['sources']:
                sanitizers.append((sanitizer, pattern['vulnerability'], source))

def mergeListsOrdered(list1, list2):
    seen = set()
    result = []
    
    for item in list1:
        if item not in seen:
            result.append(item)
            seen.add(item)
    
    for item in list2:
        if item not in seen:
            result.append(item)
            seen.add(item)
    
    return result

def getIdentifierArgs(node):
    if isinstance(node, dict):
        identifiers = []
        if node['type'] == "Identifier":
            identifiers.append(node['name'])
        elif node['type'] == "CallExpression":
            for arg in node['arguments']:
                identifiers += getIdentifierArgs(arg)
        elif node['type'] == "BinaryExpression":
            identifiers += getIdentifierArgs(node['left']) + getIdentifierArgs(node['right'])

        return identifiers

class Label:
    def __init__(self, line):
        self.line = line

    def to_dict(self):
        """Convert Label object to a dictionary."""
        return {
            "line": self.line
        }

    def __str__(self):
        """Define what print() outputs for a Label object."""
        return json.dumps(self.to_dict(), indent=4)
        
class Vuln(Label):
    def __init__(self, vuln, source, sourceline, sink, sinkline, unsanitized_flows, sanitized_flows, implicit, line):
        super().__init__(line)
        self.vuln = vuln
        self.source = source
        self.sourceline = sourceline
        self.sink = sink
        self.sinkline = sinkline
        self.unsanitized_flows = unsanitized_flows
        self.sanitized_flows = sanitized_flows
        self.implicit = implicit

    def to_dict(self):
        """Convert Vuln object to a dictionary."""
        return {
            "vulnerability": self.vuln,
            "source": [self.source, self.sourceline],
            "sink": [self.sink, self.sinkline],
            "unsanitized_flows": self.unsanitized_flows,
            "sanitized_flows": self.sanitized_flows,
            "implicit": self.implicit
        }

    def __str__(self):
        return json.dumps(self.to_dict(), indent=4)

class Source(Label):
    def __init__(self, vuln, source, line):
        super().__init__(line)
        self.vuln = vuln
        self.source = source
        self.unsanitized = "yes"
        self.sanitized = []

    def to_dict(self):
        """Convert Source object to a dictionary."""
        return {
            "vulnerability": ["SOURCE_FOR_" + self.vuln, self.line],
            "source": self.source,
            "unsanitized": self.unsanitized,
            "sanitized": self.sanitized
        }

    def __str__(self):
        return json.dumps(self.to_dict(), indent=4)
        
class Sink(Label):
    def __init__(self, vuln, sink, line):
        super().__init__(line)
        self.vuln = vuln
        self.sink = sink

    def to_dict(self):
        """Convert Sink object to a dictionary."""
        return {
            "vulnerability": ["SINK_FOR_" + self.vuln, self.line],
            "sink": self.sink
        }

    def __str__(self):
        return json.dumps(self.to_dict(), indent=4)
    
class Sanitizer(Label):
    def __init__(self, vuln, sanitizer, identifier, source, line):
        super().__init__(line)
        self.vuln = vuln
        self.sanitizer = sanitizer
        self.identifier = identifier
        self.source = source

    def to_dict(self):
        """Convert Sanitizer object to a dictionary."""
        return {
            "vulnerability": ["SANITIZER_FOR_" + self.vuln, self.line],
            "identifier": self.identifier,
            "sanitizer": self.sanitizer,
            "source": self.source
        }

    def __str__(self):
        return json.dumps(self.to_dict(), indent=4)

class LabelList:
    def __init__(self):
        self.sources = []
        self.sinks = []
        self.vulns = []
        self.sanitizers = []
        
    def mergeWith(self, other: LabelList):
        self.sources = mergeListsOrdered(self.sources, other.sources)
        self.sinks = mergeListsOrdered(self.sinks, other.sinks)
        self.vulns = mergeListsOrdered(self.vulns, other.vulns)
        self.sanitizers = mergeListsOrdered(self.sanitizers, other.sanitizers)
        
    @staticmethod
    def findExplicitVulns(sinks, sources, node):
        vulns = []
        for sink in sinks:
            for source in sources:
                sanitized_flows = []
                if sink.vuln == source.vuln and (source.vuln, source.source, source.line, sink.sink, sink.line) not in found_vulns:
                    for sanitizer in node['LabelList'].sanitizers:
                        if source.vuln == sanitizer.vuln and source.source == sanitizer.source:
                            sanitized_flows.append([sanitizer.sanitizer, sanitizer.line])
                    vulns.append(Vuln(getSequentialId(sink.vuln), source.source, source.line, sink.sink, sink.line, source.unsanitized, sanitized_flows, "no", node['loc']['start']['line']))
                    found_vulns.append((source.vuln, source.source, source.line, sink.sink, sink.line))

        return vulns
    
    def to_list(self):
        return [
            vuln.to_dict() for vuln in self.vulns
        ]

    def to_dict(self):
        """Convert the LabelList to a dictionary."""
        return {
            "vulns": [vuln.to_dict() for vuln in self.vulns],
            "sources": [source.to_dict() for source in self.sources],
            "sinks": [sink.to_dict() for sink in self.sinks],
            "sanitizers": [sanitizer.to_dict() for sanitizer in self.sanitizers],
        }

    def __str__(self):
        """Define what print() outputs for a LabelList object."""
        return json.dumps(self.to_dict(), indent=4)              
    
def searchVulnerabilityDict(identifier):   # Returns the vulnerability patterns associated to the identifier
    source_patterns = []
    sink_patterns = []
    for pattern in vuln_dict:
        for source_id in pattern['sources']:
            if source_id == identifier:
                source_patterns.append(pattern)
        for sink_id in pattern['sinks']:
            if sink_id == identifier:
                sink_patterns.append(pattern)
                
    return source_patterns, sink_patterns

def searchVulnerabilityDictSources(identifier):   # Returns the vulnerability patterns associated to the identifier
    source_patterns = []
    for pattern in vuln_dict:
        for source_id in pattern['sources']:
            if source_id == identifier:
                source_patterns.append(pattern)
                
    return source_patterns

def searchVulnerabilityDictSinks(identifier):   # Returns the vulnerability patterns associated to the identifier
    sink_patterns = []
    for pattern in vuln_dict:
        for sink_id in pattern['sinks']:
            if sink_id == identifier:
                sink_patterns.append(pattern)
                
    return sink_patterns

def getVulnerabilityPattern(vuln):  # Gets the vulnerability pattern corresponding to that vulnerability
    for pattern in vuln_dict:
        if pattern['vulnerability'] == vuln:
            return pattern

def get_node_name(node):
    match node['type']:
        case "Identifier":
            return node['name']
        case "CallExpression":
            return node['callee']['name']
        case _:
            return None
        
sanitized_identifiers = {} # Dict of identifiers that are sanitized and their location
sanitized_args = {} # Dict of arguments that are sanitized and their location
        
# NOTE: CURRENTLY UNUSED!
def check_sanitized(identifier, node):
    if identifier not in sanitized_identifiers:
        return
    
    for aux in sanitized_identifiers[identifier]:
        if node['loc']['start']['line'] < aux['loc']['start']['line']:
            continue
        if aux['loc']['end']['line'] != 0: # 0 means that the identifier is sanitized the rest of the program
            if node['loc']['start']['column'] > aux['loc']['start']['column']:
                continue
        if node['loc']['start']['line'] == aux['loc']['end']['line']:
            if node['loc']['start']['column'] < aux['loc']['end']['column']:
                continue
        vuln = aux['vulnerability']
        sanitizer = aux['sanitizer']
        source = aux['source']
        line = aux['loc']['start']['line']
        print(f"ADDED SANITIZER {sanitizer} for {identifier}")
        node['LabelList'].sanitizers.append(Sanitizer(vuln, sanitizer, identifier, source, line))


new_identifiers = {}  # Dict of identifier to their LabelList to keep track of new declared identifiers and the vulnerabilities
          
# Traverses every node in the AST
def traverse(node, left=True):
    if isinstance(node, dict):
        match node.get('type'):
            case 'Program':
                label_program(node)
            case 'ExpressionStatement':
                label_expressionstmt(node)
            case 'AssignmentExpression':
                label_assignment(node)
            case 'Identifier' if left:
                label_identifier_left(node)
            case 'Identifier' if not left:
                label_identifier_right(node)
            case 'CallExpression':
                label_call(node)
            case 'Literal':
                label_literal(node)
            case 'BinaryExpression':
                label_binaryexpr(node)
            case _:
                print("Error: Unknown node type")


# Root node
def label_program(node):
    print("Labeling program")
    if isinstance(node, dict):
        node['LabelList'] = LabelList()         
        for stmt in node['body']:
            traverse(stmt)
            node['LabelList'].mergeWith(stmt['LabelList'])   # Accumulates all found vulnerabilities
            #print("added " + str(stmt['LabelList']) + " to Program node")
        #print("Program node vulns: " + str(node['LabelList']))

def label_expressionstmt(node):
    print("Labeling expressionstmt")
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        expression = node['expression']
        traverse(expression)
        node['LabelList'].mergeWith(expression['LabelList'])  # Accumulates the vulnerabilites of the expression it states
        #print("Expression node vulns: " + str(node['LabelList']))

def label_assignment(node):
    print("Labeling assignment")
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        left = node['left']
        right = node['right']
        traverse(left)
        traverse(right, False)
        node['LabelList'].mergeWith(left['LabelList'])      # Accumulate vulnerabilities of both sides of the assignment
        node['LabelList'].mergeWith(right['LabelList'])
        explicit_vulnerabilities = LabelList.findExplicitVulns(left['LabelList'].sinks, right['LabelList'].sources, node)  # Add new explicit vulnerabilities found
        node['LabelList'].vulns += explicit_vulnerabilities
        
        new_identifiers[left['name']] = node['LabelList']  # Add left identifier and LabelList for future use

        leftName = get_node_name(left)
        rightName = get_node_name(right)
        for sanitizer in sanitizers:
            if rightName == sanitizer[0]:
                if sanitized_identifiers.get(leftName) == None:
                    sanitized_identifiers[leftName] = []
                print("SANITIZED: " + rightName + " sanitized " + leftName + " in line " + str(left['loc']['start']))
                print(sanitizer[0])
                aux_dict = {}
                aux_dict['sanitizer'] = rightName
                aux_dict['vulnerability'] = sanitizer[1]
                aux_dict['source'] = sanitizer[2]
                aux_dict['loc'] = {}
                aux_dict['loc']['start'] = left['loc']['start']
                aux_dict['loc']['end'] = {'line': 0, 'column': 0}
                sanitized_identifiers[leftName].append(aux_dict)
                print("Sanitized identifiers: " + str(sanitized_identifiers))
             
        
def label_identifier_left(node):
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        identifier = node['name']
        print("Labeling identifier (left) " + identifier)
        
        sink_patterns = searchVulnerabilityDictSinks(identifier)
        for pattern in sink_patterns:
            node['LabelList'].sinks.append(Sink(pattern['vulnerability'], identifier, node['loc']['start']['line']))
                
        #print(f"node {node['name']}'s sources: {node['LabelList'].sources}")
        #print("Identifier Left node vulns: " + str(node['LabelList']))

def label_identifier_right(node):
    if isinstance(node, dict):
        print("Labeling identifier (right)")
        print(f"{node['name']} in new_identifiers? - {node['name'] in new_identifiers}")
        node['LabelList'] = LabelList()
        identifier = node['name']
        if identifier in new_identifiers:
            node['LabelList'].mergeWith(new_identifiers[identifier])
            source_patterns = searchVulnerabilityDictSources(identifier)
            for pattern in source_patterns:
                node['LabelList'].sources.append(Source(pattern['vulnerability'], identifier, node['loc']['start']['line']))
        else:
            sink_patterns = searchVulnerabilityDictSinks(identifier)
            for pattern in sink_patterns:
                node['LabelList'].sinks.append(Sink(pattern['vulnerability'], identifier, node['loc']['start']['line']))
            for sanitizer in sanitizers:
                if identifier == sanitizer[0]: # Identifier is a Sanitizer
                    for arg in sanitized_args: # Identifier sanitizes its arguments
                        node['LabelList'].sanitizers.append(Sanitizer(sanitizer[1], identifier, arg, sanitizer[2], node['loc']['start']['line']))
                    return
            
            source_to = []
            for pattern in vuln_dict:
                if identifier in pattern['sources']:
                    source_to.append(pattern)
            if source_to != []:
                for pattern in source_to:
                    node['LabelList'].sources.append(Source(pattern['vulnerability'], identifier, node['loc']['start']['line']))
            else:
                for pattern in vuln_dict:
                    node['LabelList'].sources.append(Source(pattern['vulnerability'], identifier, node['loc']['start']['line']))
        #print("Identifier Right node vulns: " + str(node['LabelList']))

def label_literal(node):
    print("Labeling literal")
    if isinstance(node, dict):
        node['LabelList'] = LabelList()

def label_call(node):
    print("Labeling call")
    if isinstance(node, dict):
        callee = node["callee"]
        arguments = node["arguments"]
        node['LabelList'] = LabelList()

        sanitized_args = {}
        for arg in arguments:
            print("traversing argument")
            traverse(arg, False)
        for sanitizer in sanitizers:
            if callee['name'] == sanitizer[0]:
                for arg in arguments:
                    leftName = get_node_name(arg)
                    rightName = callee['name']
                    if leftName != None:
                        arg['LabelList'].sanitizers.append(Sanitizer(sanitizer[1], sanitizer[0], get_node_name(arg), sanitizer[2], node['loc']['start']['line']))
                        if sanitized_args.get(leftName) == None:
                            sanitized_args[leftName] = []
                        print("SANITIZED ARGUMENT: " + rightName + " sanitized " + leftName + " in line " + str(arg['loc']['start']))
                        print(sanitizer[0])
                        aux_dict = {}
                        aux_dict['sanitizer'] = rightName
                        aux_dict['vulnerability'] = sanitizer[1]
                        aux_dict['source'] = sanitizer[2]
                        aux_dict['loc'] = {}
                        aux_dict['loc']['start'] = arg['loc']['start']
                        aux_dict['loc']['end'] = {'line': 0, 'column': 0}
                        sanitized_args[leftName].append(aux_dict)
                        print("Sanitized args: " + str(sanitized_args))

        print("callee = " + str(callee))
        traverse(callee, False)
        node['LabelList'].mergeWith(callee['LabelList'])   # Accumulates the vulnerabilites of the expression it states

        explicit_vulnerabilities = []
            
        for arg in arguments:
            node['LabelList'].mergeWith(arg['LabelList'])
            print(f"node {get_node_name(node)} merging with arg {get_node_name(arg)}")

            explicit_vulnerabilities += LabelList.findExplicitVulns(callee['LabelList'].sinks, arg['LabelList'].sources, node)

        sanitized_args = {}
        node['LabelList'].vulns += explicit_vulnerabilities
        print("Call node vulns: " + str(node['LabelList']))
        
def label_binaryexpr(node):
    print("Labelling binary expression")
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        left = node['left']
        right = node['right']
        traverse(left, False)
        traverse(right, False)
        node['LabelList'].mergeWith(left['LabelList'])
        node['LabelList'].mergeWith(right['LabelList'])

def main(vulnDict, root):
    global vuln_dict
    vuln_dict = vulnDict
    #parseVulnerabilityDict(vuln_dict)
    matchSanitizers()
    traverse(root)
    with open(f"test_tree.json", "w") as outfile: 
        json.dump(root['LabelList'].to_list(), outfile, indent=4)
