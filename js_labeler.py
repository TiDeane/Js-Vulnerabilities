from __future__ import annotations
from typing import List, Dict
import json
import copy

sequentialIds = {} # Dict of vulnerabilities to their number of occurences
sanitizers = {} # Dict of sanitizer identifiers to their sources
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
            sanitizers[sanitizer] = []
            for source in pattern['sources']:
                sanitizers[sanitizer] = source

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

class LabelList:
    def __init__(self):
        self.sources = []
        self.sinks = []
        self.vulns = []
        
    def mergeWith(self, other: LabelList):
        self.sources = mergeListsOrdered(self.sources, other.sources)
        self.sinks = mergeListsOrdered(self.sinks, other.sinks)
        self.vulns = mergeListsOrdered(self.vulns, other.vulns)
        
    @staticmethod
    def findExplicitVulns(sinks, sources, line):
        vulns = []
        for sink in sinks:
            for source in sources:
                if sink.vuln == source.vuln and (source.vuln, source.source, source.line, sink.sink, sink.line) not in found_vulns:
                    vulns.append(Vuln(getSequentialId(sink.vuln), source.source, source.line, sink.sink, sink.line, source.unsanitized, source.sanitized, "no", line))
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
            #"sources": [source.to_dict() for source in self.sources],
            #"sinks": [sink.to_dict() for sink in self.sinks],
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
    #print("Labeling program")
    if isinstance(node, dict):
        node['LabelList'] = LabelList()         
        for stmt in node['body']:
            traverse(stmt)
            node['LabelList'].mergeWith(stmt['LabelList'])   # Accumulates all found vulnerabilities
            #print("added " + str(stmt['LabelList']) + " to Program node")
        #print("Program node vulns: " + str(node['LabelList']))

def label_expressionstmt(node):
    #print("Labeling expressionstmt")
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        expression = node['expression']
        traverse(expression)
        node['LabelList'].mergeWith(expression['LabelList'])  # Accumulates the vulnerabilites of the expression it states
        #print("Expression node vulns: " + str(node['LabelList']))

def label_assignment(node):
    #print("Labeling assignment")
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        left = node['left']
        right = node['right']
        traverse(left)
        traverse(right, False)
        node['LabelList'].mergeWith(left['LabelList'])      # Accumulate vulnerabilities of both sides of the assignment
        node['LabelList'].mergeWith(right['LabelList'])
        explicit_vulnerabilities = LabelList.findExplicitVulns(left['LabelList'].sinks, right['LabelList'].sources, node['loc']['start']['line'])  # Add new explicit vulnerabilities found
        node['LabelList'].vulns += explicit_vulnerabilities
        
        new_identifiers[left['name']] = node['LabelList']  # Add left identifier and LabelList for future use
        #print("Assignment node vulns: " + str(node['LabelList']))
             
        
def label_identifier_left(node):
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        identifier = node['name']
        #print("Labeling identifier (left) " + identifier)
        
        sink_patterns = searchVulnerabilityDictSinks(identifier)
        for pattern in sink_patterns:
            node['LabelList'].sinks.append(Sink(pattern['vulnerability'], identifier, node['loc']['start']['line']))
                
        #print(f"node {node['name']}'s sources: {node['LabelList'].sources}")
        #print("Identifier Left node vulns: " + str(node['LabelList']))

def label_identifier_right(node):
    if isinstance(node, dict):
        #print(f"{node['name']} in new_identfiers? - {node['name'] in new_identifiers}")
        node['LabelList'] = LabelList()
        identifier = node['name']
        if identifier in new_identifiers:
            node['LabelList'].mergeWith(new_identifiers[identifier])
            source_patterns = searchVulnerabilityDictSources(identifier)
            for pattern in source_patterns:
                node['LabelList'].sources.append(Source(pattern['vulnerability'], identifier, node['loc']['start']['line']))
        else:
            if identifier in sanitizers:
                return
            is_source = False
            for pattern in vuln_dict:
                if identifier in pattern['sources']:
                    is_source = True
                    break
            if is_source:
                node['LabelList'].sources.append(Source(pattern['vulnerability'], identifier, node['loc']['start']['line']))
            else:
                for pattern in vuln_dict:
                    node['LabelList'].sources.append(Source(pattern['vulnerability'], identifier, node['loc']['start']['line']))
            sink_patterns = searchVulnerabilityDictSinks(identifier)
            for pattern in sink_patterns:
                node['LabelList'].sinks.append(Sink(pattern['vulnerability'], identifier, node['loc']['start']['line']))
        #print("Identifier Right node vulns: " + str(node['LabelList']))

def label_literal(node):
    #print("Labeling literal")
    if isinstance(node, dict):
        node['LabelList'] = LabelList()

def label_call(node):
    print("Labeling call")
    if isinstance(node, dict):
        callee = node["callee"]
        node['LabelList'] = LabelList()
        print("callee = " + str(callee))
        traverse(callee, False)
        print("callee sources: " + str(callee['LabelList'].sources))
        print("callee sinks: " + str(callee['LabelList'].sinks))
        node['LabelList'].mergeWith(callee['LabelList'])   # Accumulates the vulnerabilites of the expression it states

        explicit_vulnerabilities = []
        arguments = node["arguments"]

        for arg in arguments:
            traverse(arg, False)
            #print("arg labelist sources")
            #print(arg['LabelList'].sources)
            node['LabelList'].mergeWith(arg['LabelList'])
            explicit_vulnerabilities += LabelList.findExplicitVulns(callee['LabelList'].sinks, arg['LabelList'].sources, node['loc']['start']['line'])

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
        #print(left['LabelList'].sources)
        #print(right['LabelList'].sources)
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
