from __future__ import annotations
import json
import copy
from collections import deque

vulnerabilities = []  # List of found vulnerabilities
active_contexts = [{}]  # List of contexts (Dict of identifier to their LabelList to keep track of new declared identifiers)
implicit_sources = deque()  # List of sources from the guard of the most recent if or while

def addSequentialIds():             
    sequentialIds = {}
    for vuln in vulnerabilities:
        if vuln.vuln[0] in sequentialIds:
            sequentialIds[vuln.vuln[0]] += 1
        else:
            sequentialIds[vuln.vuln[0]] = 1
        vuln.vuln += "_" + str(sequentialIds[vuln.vuln[0]])     # Adds a number to each of the vulnerablities (B_1, B_2 Etc)

def addVulnerability(new_vuln: Vuln):
        for vuln in vulnerabilities:
            if vuln.vuln == new_vuln.vuln and vuln.source == new_vuln.source and vuln.sink == new_vuln.sink and vuln.sourceline == new_vuln.sourceline and vuln.sinkline == new_vuln.sinkline:
                if new_vuln.sanitized_flows == vuln.sanitized_flows:
                    return
                vuln.sanitized_flows += new_vuln.sanitized_flows
                vuln.unsanitized_flows = "yes" if new_vuln.sanitized_flows == [] else vuln.unsanitized_flows
                return
        vulnerabilities.append(new_vuln)              # Adds a vulnerability or just a new flow if it already exists
        
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
        self.sanitized_flows = [sanitized_flows] if sanitized_flows != [] else []
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
    def __init__(self, vuln, source, unsanitized, sanitized, line, sanitizers, implicit="no"):
        super().__init__(line)
        self.vuln = vuln
        self.source = source
        self.unsanitized = unsanitized
        self.sanitized = sanitized
        self.sanitizers = copy.copy(sanitizers)
        self.implicit = implicit
        
    def equals(self, other):
        return self.vuln == other.vuln and self.source == other.source and self.sanitized == other.sanitized

    def to_dict(self):
        """Convert Source object to a dictionary."""
        return {
            "vulnerability": ["SOURCE_FOR_" + self.vuln, self.line],
            "source": self.source,
            "unsanitized": self.unsanitized,
            "sanitized": self.sanitized,
            "implicit": self.implicit
        }

    def __str__(self):
        return json.dumps(self.to_dict(), indent=4)
        
class Sink(Label):
    def __init__(self, vuln, sink, implicit, line):
        super().__init__(line)
        self.vuln = vuln
        self.sink = sink
        self.implicit = implicit
        
    def equals(self, other):
        return self.vuln == other.vuln and self.sink == other.sink and self.implicit == other.implicit

    def to_dict(self):
        """Convert Sink object to a dictionary."""
        return {
            "vulnerability": ["SINK_FOR_" + self.vuln, self.line],
            "sink": self.sink,
            "implicit": self.implicit
        }

    def __str__(self):
        return json.dumps(self.to_dict(), indent=4)

class LabelList:
    def __init__(self):
        self.sources = []
        self.sinks = []
        
    @staticmethod
    def findExplicitVulns(sinks, sources, line):
        for sink in sinks:
            for source in sources:
                if sink.vuln == source.vuln and not (sink.implicit == "no" and source.implicit == "yes"):
                    addVulnerability(Vuln(sink.vuln, source.source, source.line, sink.sink, sink.line, source.unsanitized, source.sanitized, source.implicit, line))
                    
    def inSources(self, vuln, identifier, implicit = "no"):
        for source in self.sources:
            if source.vuln == vuln and source.source == identifier and source.implicit == implicit:
                return True
        return False
    
    def inSinks(self, vuln, identifier):
        for sink in self.sinks:
            if sink.vuln == vuln and sink.sink == identifier:
                return True
        return False
    
    def equals(self, other):
        if len(self.sources) != len(other.sources) or len(self.sinks) != len(other.sinks):
            return False

        return all(any(obj1.equals(obj2) for obj2 in other.sources) for obj1 in self.sources) and all(any(obj1.equals(obj2) for obj2 in other.sinks) for obj1 in self.sinks)


    def to_dict(self):
        """Convert the LabelList to a dictionary."""
        return {
            "sources": [source.to_dict() for source in self.sources],
            "sinks": [sink.to_dict() for sink in self.sinks],
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
        
def isSanitizer(identifier):
    for pattern in vuln_dict:
        for sanitizer in pattern['sanitizers']:
            if identifier == sanitizer:
                return True
    return False
          
# Traverses every node in the AST
def traverse(node, left=True, func=False):
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
                label_identifier_right(node, func)
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
            case 'WhileStatement':
                label_whilestmt(node)
            case _:
                print("Error: Unknown node type")


# Root node
def label_program(node):
    if isinstance(node, dict):        
        for stmt in node['body']:
            traverse(stmt)

def label_expressionstmt(node):
    if isinstance(node, dict):
        expression = node['expression']
        traverse(expression)
        node['LabelList'] = copy.deepcopy(expression['LabelList'])

def label_assignment(node):
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        left = node['left']
        right = node['right']
        traverse(left)
        traverse(right, False)
        node['LabelList'].sinks = copy.deepcopy(left['LabelList'].sinks)
        for sink in copy.deepcopy(right['LabelList'].sinks):
            if not node['LabelList'].inSinks(sink.vuln, sink.sink):
                node['LabelList'].sinks.append(sink)
        
        for source in right['LabelList'].sources:  # Copy sources
            if not node['LabelList'].inSources(source.vuln, source.source, source.implicit):
                node['LabelList'].sources.append(copy.deepcopy(source))
        
        if implicit_sources != deque():
            for context in implicit_sources:
                for source in context:
                    if not node['LabelList'].inSources(source.vuln, source.source, source.implicit):
                        node['LabelList'].sources.append(copy.deepcopy(source))
                        """
                        print("FROM IMPLICIT")
                        print(node['loc']['start'])
                        print(source)
                        """
            
        LabelList.findExplicitVulns(left['LabelList'].sinks, right['LabelList'].sources, node['loc']['start']['line'])  # Add new explicit vulnerabilities found
        
        if left['type'] == "MemberExpression":
            return

        for context in active_contexts:
            context[left['name']] = node['LabelList']  # Add left identifier and LabelList for future use
             
        
def label_identifier_left(node):
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        identifier = node['name']
            
        sink_patterns = searchVulnerabilityDictSinks(identifier)
        for pattern in sink_patterns:
            node['LabelList'].sinks.append(Sink(pattern['vulnerability'], identifier, pattern['implicit'], node['loc']['start']['line']))

def label_identifier_right(node, func):
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        identifier = node['name']

        for context in active_contexts:
            if identifier in context:        # If the identifier is already registered get its label, and add any remaining sources it may have
                node['LabelList'].sinks += copy.deepcopy(context[identifier].sinks)
                node['LabelList'].sources += copy.deepcopy(context[identifier].sources)
                source_patterns = searchVulnerabilityDictSources(identifier)
                for pattern in source_patterns:
                    if not node['LabelList'].inSources(pattern['vulnerability'], identifier, pattern['implicit']):
                        node['LabelList'].sources.append(Source(pattern['vulnerability'], identifier, "yes", [], node['loc']['start']['line'], pattern['sanitizers']))
                
            else:                                   # Else add the sources and sinks from the vuln_dict directly, if there is no information about the identifier assume all sources or sinks
                source_patterns, sink_patterns = searchVulnerabilityDict(identifier)
                sanitizer = isSanitizer(identifier)

                if source_patterns == [] and not sanitizer and not func:
                    for source in addAllSources(identifier, node['loc']['start']['line']):
                        if not node['LabelList'].inSources(source.vuln, source.source, source.implicit):
                            node['LabelList'].sources.append(Source(source.vuln, source.source, "yes", [], node['loc']['start']['line'], source.sanitizers))
            
                if sink_patterns == [] and not sanitizer and not func:
                    for sink in addAllSinks(identifier, node['loc']['start']['line']):
                        if not node['LabelList'].inSinks(sink.vuln, sink.sink):
                            node['LabelList'].sinks.append(Sink(sink.vuln, sink.sink, sink.implicit, node['loc']['start']['line']))

                for pattern in source_patterns:
                    if not node['LabelList'].inSources(pattern['vulnerability'], identifier, pattern['implicit']):
                        node['LabelList'].sources.append(Source(pattern['vulnerability'], identifier, "yes", [], node['loc']['start']['line'], pattern['sanitizers']))
                for pattern in sink_patterns:
                    if not node['LabelList'].inSinks(pattern['vulnerability'], identifier):
                        node['LabelList'].sinks.append(Sink(pattern['vulnerability'], identifier, pattern['implicit'], node['loc']['start']['line']))   
                
def addAllSources(identifier, line):
    result = []
    for pattern in vuln_dict:
        result.append(Source(pattern['vulnerability'], identifier, "yes", [], line, pattern['sanitizers']))
        
    return result

def addAllSinks(identifier, line):
    result = []
    for pattern in vuln_dict:
        result.append(Sink(pattern['vulnerability'], identifier, pattern['implicit'], line))
        
    return result
        
def label_literal(node):
    if isinstance(node, dict):
        node['LabelList'] = LabelList()

def label_call(node):
    if isinstance(node, dict):
        callee = node["callee"]
        node['LabelList'] = LabelList()
    
        traverse(callee, False, func=True)
        
        for source in callee['LabelList'].sources:     # Copy callee's sources and sinks
            node['LabelList'].sources.append(Source(source.vuln, source.source, source.unsanitized, source.sanitized, node['loc']['start']['line'], source.sanitizers))
            
        for sink in callee['LabelList'].sinks:
            node['LabelList'].sinks.append(Sink(sink.vuln, sink.sink, sink.implicit, node['loc']['start']['line']))

        arguments = node["arguments"]

        if implicit_sources != deque():
            for context in implicit_sources:
                for source in context:
                    if not node['LabelList'].inSources(source.vuln, source.source, source.implicit):
                        node['LabelList'].sources.append(copy.deepcopy(source))
                
            LabelList.findExplicitVulns(callee['LabelList'].sinks, node['LabelList'].sources, node['loc']['start']['line'])

        for arg in arguments:
            traverse(arg, False)

            for source in arg['LabelList'].sources:     # Check for sanitization and add sources
                if callee['name'] in source.sanitizers:
                    if [callee['name'], node['loc']['start']['line']] not in source.sanitized:
                        source.sanitized.append([callee['name'], node['loc']['start']['line']])
                        source.unsanitized = "no"
                node['LabelList'].sources.append(copy.deepcopy(source))
                
            LabelList.findExplicitVulns(callee['LabelList'].sinks, arg['LabelList'].sources, node['loc']['start']['line'])

def label_binaryexpr(node):
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        left = node['left']
        right = node['right']
        traverse(left, False)
        traverse(right, False)
        node['LabelList'].sinks += copy.deepcopy(left['LabelList'].sinks) + copy.deepcopy(right['LabelList'].sinks)
        node['LabelList'].sources += copy.deepcopy(left['LabelList'].sources) + copy.deepcopy(right['LabelList'].sources)

def label_memberexpr_left(node):
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        obj = node['object']
        attr = node['property']
        traverse(obj, True)
        traverse(attr, False, True)

        node['LabelList'].sinks += copy.deepcopy(obj['LabelList'].sinks)
        node['LabelList'].sources += copy.deepcopy(obj['LabelList'].sources)

        node['LabelList'].sinks += copy.deepcopy(attr['LabelList'].sinks)
        node['LabelList'].sources += copy.deepcopy(attr['LabelList'].sources)

def label_memberexpr_right(node):
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        obj = node['object']
        attr = node['property']
        traverse(obj, False)
        traverse(attr, False, True)
        for attr_source in attr['LabelList'].sources:
            obj['LabelList'].sources.append(Source(attr_source.vuln, obj['name'], attr_source.unsanitized, attr_source.sanitized, node['loc']['start']['line'], attr_source.sanitizers))
        
        node['LabelList'].sinks += copy.deepcopy(obj['LabelList'].sinks)
        node['LabelList'].sources += copy.deepcopy(obj['LabelList'].sources)

        node['LabelList'].sinks += copy.deepcopy(attr['LabelList'].sinks)
        node['LabelList'].sources += copy.deepcopy(attr['LabelList'].sources)

def label_ifstmt(node):
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        global active_contexts
        global implicit_sources
        
        test_stmt = node['test']
        traverse(test_stmt)

        implicit_sources.append([])
        for source in test_stmt['LabelList'].sources:
            if not any(source_in.equals(source) for source_in in implicit_sources[-1]):
                implicit_sources[-1].append(Source(source.vuln, source.source, source.unsanitized, source.sanitized, source.line, source.sanitizers, implicit="yes"))
        
        # When there is an 'if' the active_contexts will be duplicated, executing the 'then' and 'else' for each
        else_contexts = copy.deepcopy(active_contexts)
        
        then_stmt = node['consequent']
        traverse(then_stmt)                 # Traverse 'then' with the current active_contexts
        then_contexts = copy.deepcopy(active_contexts)
        node['LabelList'].sinks += copy.deepcopy(then_stmt['LabelList'].sinks)
        node['LabelList'].sources += copy.deepcopy(then_stmt['LabelList'].sources)
        
        implicit_sources.pop()

        if 'alternate' in node:
            active_contexts = else_contexts
            else_stmt = node['alternate']
            traverse(else_stmt)            # Traverse 'else'
            node['LabelList'].sinks += copy.deepcopy(else_stmt['LabelList'].sinks)
            node['LabelList'].sources += copy.deepcopy(else_stmt['LabelList'].sources)

        active_contexts = then_contexts + else_contexts
        

        
        
def label_block(node):
    if isinstance(node, dict):
        node['LabelList'] = LabelList()
        for expr in node['body']:
            traverse(expr)
            node['LabelList'].sinks += copy.deepcopy(expr['LabelList'].sinks)
            node['LabelList'].sources += copy.deepcopy(expr['LabelList'].sources)
            
def label_whilestmt(node):
    if isinstance(node, dict):
        node['LabelList'] = LabelList()

        global active_contexts
        skip_contexts = []    # A while loop creates a branch where the body is not executed and one where it is
        global implicit_sources
        
        test_stmt = node['test']
        traverse(test_stmt)

        implicit_sources.append([])
        for source in test_stmt['LabelList'].sources:
            if not any(source_in.equals(source) for source_in in implicit_sources[-1]):
                implicit_sources[-1].append(Source(source.vuln, source.source, source.unsanitized, source.sanitized, source.line, source.sanitizers, implicit="yes"))

        while True:
            
            skip_contexts += copy.deepcopy(active_contexts)
            
            node_label_list_copy = copy.deepcopy(node['LabelList'])

            body_stmt = node['body']
            traverse(body_stmt)

            node['LabelList'].sinks = copy.deepcopy(body_stmt['LabelList'].sinks)
            node['LabelList'].sources = copy.deepcopy(body_stmt['LabelList'].sources)
    
            if node_label_list_copy.equals(node['LabelList']):
                break
        
        active_contexts += skip_contexts
        implicit_sources.pop()
        

def main(vulnDict, root):
    global vuln_dict
    vuln_dict = vulnDict
    traverse(root)
    addSequentialIds()
    with open(f"test_tree.json", "w") as outfile: 
        json.dump([vuln.to_dict() for vuln in vulnerabilities], outfile, indent=4)
