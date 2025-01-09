#!/bin/bash

# List of test files without extensions
tests=(
  "1a-basic-flow"
  "1b-basic-flow"
  "2-expr-binary-ops"
  "3a-expr-func-calls"
  "3b-expr-func-calls"
  "3c-expr-attributes"
  "4a-conds-branching"
  "4b-conds-branching"
  "5a-loops-unfolding"
  "5b-loops-unfolding"
  "5c-loops-unfolding"
  "6a-sanitization"
  "6b-sanitization"
  "7-conds-implicit"
  "8-loops-implicit"
  "9-regions-guards"
)

# Loop through each test
for test in "${tests[@]}"; do
  echo "Running test: $test"
  
  # Run js_analyser.py
  python3 js_analyser.py "./slices/${test}.js" "./patterns/${test}.patterns.json"
  
  # Validate the output
  python3 validate.py -p "./patterns/${test}.patterns.json" -o "./test_tree.json" -t "./output/${test}.output.json"
  
  echo "Completed test: $test"
  echo "--------------------------"
done

echo "All tests completed."
