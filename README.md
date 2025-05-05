# Discovering vulnerabilities in Javascript web applications

## The Problem

A large class of vulnerabilities in applications originates in programs that enable user input information to affect the values of certain parameters of security sensitive functions. In other words, these programs encode a potentially dangerous information flow, in the sense that low integrity -- tainted -- information (user input) may interfere with high integrity parameters of sensitive functions **or variables** (so called sensitive sinks). This means that users are given the power to alter the behavior of sensitive functions **or variables**, and in the worst case may be able to induce the program to perform security violations. For this reason, such flows can be deemed illegal for their potential to encode vulnerabilities.

It is often desirable to accept certain illegal information flows, so we do not want to reject such flows entirely. For instance, it is useful to be able to use the inputted user name for building SQL queries. It is thus necessary to differentiate illegal flows that can be exploited, where a vulnerability exists, from those that are inoffensive and can be deemed secure, or endorsed, where there is no vulnerability. One approach is to only accept programs that properly sanitize the user input, and by so restricting the power of the user to acceptable limits, in effect neutralizing the potential vulnerability.

JavaScript has been the primary language for application development in browsers, but it is increasingly becoming popular on server side development as well. However, JavaScript suffers from vulnerabilities, such as cross-site scripting and malicious advertisement code on the client side, and SQL injection on the server side.

This project detects web vulnerabilities statically using taint and input sanitization analysis. We chose as a target web server and client side programs encoded in the JavaScript language.

## Specification of the Tool

The tool performs static analysis to identify data and information flow violations that are not protected within the program. It is assumed that the code to be analyzed has undergone a pre-processing stage to isolate, in the form of a program slice, a sequence of JavaScript instructions that are considered to be relevant to our analysis.

The following code slice, which is written in JavaScript, contains code lines which may impact a data flow between a certain source and a sensitive sink. The `URL` property of the `document` object (which can be accessed in a client side script) can be understood as an entry point. It uses the `document.write` to change the html page where it is embedded.

```javascript
var pos = document.URL.indexOf("name=");
var name = document.URL.substring(pos + 5);
document.write(name);
```

Inspecting this slice it is clear that the program from which the slice was extracted could encode a DOM based XSS vulnerability. A victim can visit the page `http://www.vulnerable.com/welcome.html?name=<script>alert(document.cookie)</script>`, and the behavior of the webpage is modified and prints the cookies for the current site. However, sanitization of the untrusted input can remove the vulnerability:

```javascript
var pos = document.URL.indexOf("name=");
var name = document.URL.substring(pos + 5);
var sanitizedName = DOMPurify.sanitize(name);
document.write(sanitizedName);
```

The tool is to search the slices for vulnerabilities according to inputted patterns, which specify for a given type of vulnerability its possible sources (a.k.a. entry points), sanitizers and sinks. A _pattern_ is thus a 5-tuple with:

- name of vulnerability (e.g., DOM XSS)
- a list of sources (e.g., `document.URL`),
- a list of sanitization functions (e.g., `DOMPurify.sanitize`),
- a list of sensitive sinks (e.g., `document.write`),
- and a flag indicating whether implicit flows are to be considered.

The tool signals potential vulnerabilities and sanitization efforts: if it identifies a possible data flow from an entry point to a sensitive sink (according to the inputted patterns), it reports a potential vulnerability; if the data flow passes through a sanitization function (in other words, it is returned by the function), _it still reports the vulnerability_, but also acknowledges the fact that its sanitization is possibly being addressed.

### Running the tool

The tool should be called in the command line, receiving the following two arguments:

- a path to a Javascript file containing the program slice to analyse;
- a path to a [JSON](http://www.json.org/) file containing the list of vulnerability patterns to consider.

It is assumed that the parsing of the JavaScript slices has been done, and that the input files are well-formed. In addition to the entry points specified in the patterns, **by default any non-instantiated variable that appears in the slice should be considered as an entry point to all vulnerabilities being considered**.

The output lists the potential vulnerabilities encoded in the slice, and an indication of which sanitization functions(s) (if any) have been applied. The format of the output is specified [below](#output).

The tool is implemented in **Python, version >= 3.9.2**, and works in the following way:

    $ python ./js_analyser.py foo/slice_1.js bar/my_patterns.json

should analyse `slice_1.js` slice in folder `foo`, according to patterns in file `my_patterns.json` in folder `bar`, and output the result in file `./output/slice_1.output.json`.

### Input

#### Program slices

The JavaScript slice is read from a text file given as the first argument. It is converted into an Abstract Syntax Tree (AST) using Python's [`esprima` module](https://esprima.org/)

#### Vulnerability patterns

The patterns are to be loaded from a file, whose name is given as the second argument in the command line. You can assume that pattern names are unique within a file.

An example JSON file with two patterns:

    [
      {
        "vulnerability": "Command Injection",
        "sources": ["req.headers", "readFile"],
        "sanitizers": ["shell-escape"],
        "sinks": ["exec", "execSync", "spawnSync", "execFileSync"],
        "implicit": "no"
      },
      {
        "vulnerability": "DOM XSS",
        "sources": ["document.referrer", "document.URL", "document.location"],
        "sanitizers": ["DOMPurify.sanitize"],
        "sinks": ["document.write", "innerHTML", "setAttribute"],
        "implicit": "yes"
      }
    ]

### Output

The output of the program is a `JSON` list of vulnerability objects that is written to a file `./output/<slice>.output.json` where `<slice>.js` is the program slice under analysis. The structure of the objects includes 6 pairs, with the following meaning:

- `vulnerability`: name of vulnerability (string, according to the inputted pattern)
- `source`: input source (string, according to the inputted pattern, and line where it appears in the code)
- `sink`: sensitive sink (string, according to the inputted pattern, and line where it appears in the code)
- `implicit_flows`: whether there are implicit flows (string)
- `unsanitized_flows`: whether there are unsanitized flows (string)
- `sanitized_flows`: list of lists of the sanitizing functions (string, according to the inputted pattern, and line where it appears in the code) if present, otherwise empty (list of lists of pairs)

As an example, the output with respect to the program and patterns that appear in the examples in [Specification of the Tool](#specification-of-the-tool) would be:

    [
        {
            "vulnerability": "DOM XSS",
            "source": ["document.URL", 1],
            "sink": ["document.write", 4],
            "implicit_flows": "no",
            "unsanitized_flows": "no",
            "sanitized_flows": [[["DOMPurify.sanitize", 3]]]
        },
        {
            "vulnerability": "DOM XSS",
            "source": ["document.URL", 2],
            "sink": ["document.write", 4],
            "implicit_flows": "no",
            "unsanitized_flows": "no",
            "sanitized_flows": [[["DOMPurify.sanitize", 3]]]
        }
    ]

The output list includes a vulnerability object for every pair source-sink between which there is at least one flow of information:

- If at least one of these flows corresponds to an implicit flow, it is signaled.
- If at least one of these flows is not sanitized, it is signaled. Since it is possible that there are more than one flow paths for a given pair source-sink, that could be sanitized in different ways, sanitized flows are represented as a list. Since each flow might be sanitized by more than one sanitizer, each flow is itself a list (with no particular order).

More precisely, the format of the output should be:

    <OUTPUT> ::= [ <VULNERABILITIES> ]
    <VULNERABILITIES> := "none" | <VULNERABILITY> | <VULNERABILITY>, <VULNERABILITIES>
    <VULNERABILITY> ::= { "vulnerability": "<STRING>",
                        "source": [ "<STRING>", <INT> ]
                        "sink": [ "<STRING>", <INT> ],
                        "implicit_flows": <YESNO>,
                        "unsanitized_flows": <YESNO>,
                        "sanitized_flows": [ <FLOWS> ] }
    <YESNO> ::= "yes" | "no"
    <FLOWS> ::= "none" | <FLOW> | <FLOW>, <FLOWS>
    <FLOW> ::= [ <SANITIZERS> ]
    <SANITIZERS> ::= [ <STRING>, <INT> ] | [ <STRING>, <INT> ], <SANITIZERS>

_Note_: A flow is said to be sanitized if it goes "through" an appropriate sanitizer, i.e., if at some point the entire information is converted into the output of a sanitizer.
