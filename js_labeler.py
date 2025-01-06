from __future__ import annotations
from typing import List, Dict
import json
import copy

sequentialIds = {} # Dict of vulnerabilities to their number of occurences
sanitizers = [] # List of (sanitizer, vuln, source) tuples
found_vulns = [] # UNUSED: List of (vuln, source, source_line, sink, sink_line) tuples

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
        update_vuln = False
        # check if vulnerability already exists
        if isinstance(item, Vuln):
            for seen_item in seen:
                if isinstance(seen_item, Vuln):
                    if item.is_same_vuln(seen_item):
                        # if it does, merge sanitized and unsanitized flows instead of creating another vulnerability
                        seen_item.merge_with_vuln(item)
                        update_vuln = True
        if item not in seen and not update_vuln:
            result.append(item)
            seen.add(item)
    
    return result

def getIdentifierArgs(node):
    if isinstance(node, dict):
        identifiers = []
        if node['type'] == "CallExpression":
            for arg in node['arguments']:
                if arg['type'] == "Identifier":
                    identifiers.append(get_node_name(arg))
                elif arg['type'] == "CallExpression":
                    identifiers += getIdentifierArgs(arg)
        
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

    def is_same_vuln(self, other):
        return self.vuln[0] == other.vuln[0] and self.source == other.source and self.sourceline == other.sourceline and self.sink == other.sink and self.sinkline == other.sinkline

    def merge_with_vuln(self, other: Vuln):
        if self.vuln == other.vuln:
            # already merged before
            return
        if other.unsanitized_flows == "yes":
            self.unsanitized_flows = "yes"
        if other.sanitized_flows != []:
            self.sanitized_flows += other.sanitized_flows
        # TODO: (maybe), this destroys sequential id

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
    def __init__(self, vuln, sanitizer, identifier, source, line, flow_id):
        super().__init__(line)
        self.vuln = vuln
        self.sanitizer = sanitizer
        self.identifier = identifier
        self.source = source
        self.flow_id = flow_id

    def to_dict(self):
        """Convert Sanitizer object to a dictionary."""
        return {
            "vulnerability": ["SANITIZER_FOR_" + self.vuln, self.line],
            "identifier": self.identifier,
            "sanitizer": self.sanitizer,
            "source": self.source,
            "flow_id": self.flow_id
        }

    def __str__(self):
        return json.dumps(self.to_dict(), indent=4)

class LabelList:
    def __init__(self):
        self.sources = []
        self.sinks = []
        self.vulns = []
        self.sanitizers = {}    # dict of lists, key is an id that indicates all sanitizers in that list belong to the same flow
        
    def mergeWith(self, other: LabelList):
        self.sources = mergeListsOrdered(self.sources, other.sources)
        self.sinks = mergeListsOrdered(self.sinks, other.sinks)
        self.vulns = mergeListsOrdered(self.vulns, other.vulns)
        self.sanitizers.update(other.sanitizers)
        
    @staticmethod
    def findExplicitVulns(node, node_aux_1, node_aux_2):
        # TODO: (maybe) change node_aux_1 and node_aux_2 name
        # node_aux_1 is left/callee
        # node_aux_2 is right/arg
        sinks = node_aux_1['LabelList'].sinks
        sources = node_aux_2['LabelList'].sources
        sanitizers = node_aux_2['LabelList'].sanitizers
        vulns = []
        for sink in sinks:
            for source in sources:
                sanitized_flows = []
                if sink.vuln == source.vuln: # and (source.vuln, source.source, source.line, sink.sink, sink.line) not in found_vulns:
                    # look at every sanitized flow and check if it belongs to the vulnerability
                    unsanitized_flows = "no"
                    if not sanitizers:
                        # no sanitizers exist
                        unsanitized_flows = "yes"
                    else:
                        for flow_id in sanitizers:
                            sanitized_flow_aux = []
                            for sanitizer in sanitizers[flow_id]:
                                if source.vuln == sanitizer.vuln and source.source == sanitizer.source:
                                    sanitized_flow_aux.append([sanitizer.sanitizer, sanitizer.line])
                            if sanitized_flow_aux == []:
                                unsanitized_flows = "yes"
                            else:
                                sanitized_flows.append(sanitized_flow_aux)
                    vulns.append(Vuln(getSequentialId(sink.vuln), source.source, source.line, sink.sink, sink.line, unsanitized_flows, sanitized_flows, "no", node['loc']['start']['line']))
                    # found_vulns.append((source.vuln, source.source, source.line, sink.sink, sink.line))
                    # I think this is no longer needed

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
            "sanitizers": [[sanitizer.to_dict() for sanitizer in sanitizer_list] for sanitizer_list in self.sanitizers.values()]
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
        case "MemberExpression":
            return node['object']['name']
        case "BinaryExpression": # just for print purposes
            return "<BinaryExpression>"
        case _:
            return None
        
sanitized_identifiers = {} # UNUSED: Dict of identifiers that are sanitized and their location

# UNUSED
def check_sanitized(identifier, node):
    if identifier not in sanitized_identifiers:
        return
    
    print(f"SANITIZED IDENTIFIERS: {sanitized_identifiers}")

    # filter same dictionary entries (IDEK if this is needed)
    for id in sanitized_identifiers:
        filter = set([])
        for l in sanitized_identifiers[id]:
            filter.add(json.dumps(l, sort_keys=True))
        res = []
        for f in filter:
            res.append(json.loads(f))
        sanitized_identifiers[id] = res
    
    print("\nS)ADUOSADI")
    print(sanitized_identifiers)
    print(node['LabelList'])
    for s in node['LabelList'].sanitizers:
        for s1 in node['LabelList'].sanitizers[s]:
            print(s1)
            print(f"LINE: {node['loc']['start']['line']}")
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
        global flow
        flow += 1
        flow_id = flow
        node['LabelList'].sanitizers[flow_id] = [] if flow_id not in node['LabelList'].sanitizers else node['LabelList'].sanitizers[flow_id]
        node['LabelList'].sanitizers[flow_id].append(Sanitizer(vuln, sanitizer, identifier, source, line, flow_id))

# Stores all identifiers as if every branch has been chosen
new_identifiers = {} # Dict of identifier to their LabelList to keep track of new declared identifiers and the vulnerabilities
# Stores identifiers as if the minimum amount of branches has been chosen (only saves the identifiers that are guaranteed to exists)
new_identifiers_context = [{}, {}, {}]  # TODO: make the size variable
level = 0 # index of new_identifiers

# Traverses every node in the AST
def traverse(node, left=True, attr=False):
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
                label_identifier_right(node, attr)
            case 'CallExpression':
                label_call(node)
            case 'Literal':
                label_literal(node)
            case 'BinaryExpression':
                label_binaryexpr(node)
            case 'MemberExpression' if left:
                label_memberexpr_left(node)
            case 'MemberExpression' if not left:
                label_memberexpr_right(node)
            case 'IfStatement':
                label_ifstmt(node)
            case 'BlockStatement':
                label_block(node)
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
        explicit_vulnerabilities = LabelList.findExplicitVulns(node, left, right)  # Add new explicit vulnerabilities found
        node['LabelList'].vulns += explicit_vulnerabilities
        if left['type'] == "MemberExpression":
            return
        new_identifiers[get_node_name(left)] = node['LabelList']  # Add left identifier and LabelList for future use
        new_identifiers_context[level][get_node_name(left)] = node['LabelList']  # (only in that level)
        print(f"Assignment node, in {node['loc']['start']}, vulns: " + str(node['LabelList']))

        # UNUSED: add to 'sanitized_identifiers'
        """
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
        """
        
        
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

def label_identifier_right(node, attr=False):
    if isinstance(node, dict):
        print("Labeling identifier (right)")
        node['LabelList'] = LabelList()
        identifier = node['name']
        in_new_identifiers_context = False
        if identifier in new_identifiers:
            node['LabelList'].mergeWith(new_identifiers[identifier])
            source_patterns = searchVulnerabilityDictSources(identifier)
            #check_sanitized(identifier, node)
            for pattern in source_patterns:
                node['LabelList'].sources.append(Source(pattern['vulnerability'], identifier, node['loc']['start']['line']))
            # check if, assuming the minimum amount of branches travelled, 'identifier' exists
            if any(identifier in new_identifiers_context[i] for i in range(0, level + 1)):
                in_new_identifiers_context = True
        print(f"{node['name']} in new_identfiers? - {node['name'] in new_identifiers}")
        print(f"{node['name']} in new_identfiers_context? - {in_new_identifiers_context}")
        if not in_new_identifiers_context:
            sink_patterns = searchVulnerabilityDictSinks(identifier)
            for pattern in sink_patterns:
                node['LabelList'].sinks.append(Sink(pattern['vulnerability'], identifier, node['loc']['start']['line']))
            for sanitizer in sanitizers:
                if identifier in sanitizer[0]:
                    return
            
            source_to = []
            for pattern in vuln_dict:
                if identifier in pattern['sources']:
                    source_to.append(pattern)
            if source_to != []:
                for pattern in source_to:
                    node['LabelList'].sources.append(Source(pattern['vulnerability'], identifier, node['loc']['start']['line']))
            else:
                if not attr:
                    for pattern in vuln_dict:
                        node['LabelList'].sources.append(Source(pattern['vulnerability'], identifier, node['loc']['start']['line']))
        #print("Identifier Right node vulns: " + str(node['LabelList']))

def label_literal(node):
    print("Labeling literal")
    if isinstance(node, dict):
        node['LabelList'] = LabelList()

flow = 0    # used to group nested calls

def label_call(node):
    print("Labeling call")
    if isinstance(node, dict):
        callee = node["callee"]
        node['LabelList'] = LabelList()
        print("callee = " + str(callee))
        traverse(callee, False, True)   # Callee identifier won't be added to 'new_identifiers'
        node['LabelList'].mergeWith(callee['LabelList'])   # Accumulates the vulnerabilites of the expression it states

        explicit_vulnerabilities = []
        arguments = node["arguments"]
        rightName = get_node_name(callee)
        global flow
        
        for arg in arguments:
            flow_id = flow  # this id will be the same in all calls that are in the same nested
            print("traversing argument")
            traverse(arg, False)
            
            leftName = get_node_name(arg)
            for sanitizer in sanitizers:
                if rightName == sanitizer[0]:
                    if leftName != None:
                        print(f"node {get_node_name(node)} merging with arg {get_node_name(arg)}")
                        arg['LabelList'].sanitizers[flow_id] = [] if flow_id not in arg['LabelList'].sanitizers else arg['LabelList'].sanitizers[flow_id]
                        arg['LabelList'].sanitizers[flow_id].append(Sanitizer(sanitizer[1], sanitizer[0], get_node_name(arg), sanitizer[2], node['loc']['start']['line'], flow_id))
                        print("SANITIZED ARGUMENT: " + rightName + " sanitized " + leftName + " in line " + str(arg['loc']['start']))
            #print(f"Arg {get_node_name(arg)} node vulns: " + str(arg['LabelList']))
            node['LabelList'].mergeWith(arg['LabelList'])
            explicit_vulnerabilities += LabelList.findExplicitVulns(node, callee, arg)
        flow += 1
        node['LabelList'].vulns += explicit_vulnerabilities
        print(f"Call node, in {node['loc']['start']}, vulns: " + str(node['LabelList']))
        
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

def label_memberexpr_left(node):
    print("Labelling member expression (left)")
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        obj = node['object']
        attr = node['property']
        traverse(obj, True)
        traverse(attr, False, True)
        node['LabelList'].mergeWith(obj['LabelList'])
        node['LabelList'].mergeWith(attr['LabelList'])
        #print("member node:\n"+str(node['LabelList']))

def label_memberexpr_right(node):
    print("Labelling member expression (right)")
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        obj = node['object']
        attr = node['property']
        print(f"traversing {obj['name']} and {attr['name']}")
        traverse(obj, False)
        traverse(attr, False, True)
        for attr_source in attr['LabelList'].sources:
            obj['LabelList'].sources.append(Source(attr_source.vuln, get_node_name(obj), node['loc']['start']['line']))
        node['LabelList'].mergeWith(obj['LabelList'])
        node['LabelList'].mergeWith(attr['LabelList'])
        #print("member node:\n"+str(node['LabelList']))

def label_ifstmt(node):
    print("Labelling if statement")
    global level
    if isinstance(node, dict):
        level += 1
        new_identifiers_context[level] = {}
        node['LabelList'] = LabelList()
        test_stmt = node ['test']
        traverse(test_stmt)
        then_stmt = node['consequent']
        traverse(then_stmt)
        node['LabelList'].mergeWith(then_stmt['LabelList'])
        new_identifiers_context[level] = {}
        level -= 1
        if 'alternate' in node:
            level +=1
            new_identifiers_context[level] = {}
            else_stmt = node['alternate']
            traverse(else_stmt)
            node['LabelList'].mergeWith(else_stmt['LabelList'])
            new_identifiers_context[level] = {}
            level -=1

def label_block(node):
    print("Labelling block statement")
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        for expr in node['body']:
            traverse(expr)
            node['LabelList'].mergeWith(expr['LabelList'])


def main(vulnDict, root):
    global vuln_dict
    vuln_dict = vulnDict
    #parseVulnerabilityDict(vuln_dict)
    matchSanitizers()
    traverse(root)
    with open(f"test_tree.json", "w") as outfile: 
        json.dump(root['LabelList'].to_list(), outfile, indent=4)
