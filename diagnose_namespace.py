"""
Diagnostic script to analyze namespace handling in XCCDF scan files.
This helps identify why benchmark details might not be extracting.
"""

import xml.etree.ElementTree as ET
import os
import glob

def diagnose_scan_file(xml_path):
    """Analyze a scan file's namespace and structure."""
    print("=" * 80)
    print(f"Analyzing: {os.path.basename(xml_path)}")
    print("=" * 80)
    
    with open(xml_path, 'rb') as f:
        content = f.read()
    
    # Parse XML
    root = ET.fromstring(content)
    
    # Step 1: Detect namespace from root
    print("\n--- STEP 1: Root Element Analysis ---")
    print(f"Root tag: {root.tag}")
    
    if root.tag.startswith('{'):
        scan_ns_uri = root.tag.split('}')[0][1:]
        scan_ns = {'xccdf': scan_ns_uri}
        print(f"✓ Namespace detected: {scan_ns_uri}")
    else:
        scan_ns = {}
        print("⚠ No namespace in root element")
    
    # Step 2: Look for embedded benchmark
    print("\n--- STEP 2: Embedded Benchmark Check ---")
    benchmark = root.find('.//xccdf:Benchmark', scan_ns)
    if benchmark is not None:
        groups = benchmark.findall('.//xccdf:Group', scan_ns)
        print(f"✓ Found embedded Benchmark with {len(groups)} Groups")
        embedded = True
    else:
        print("✗ No embedded Benchmark found")
        embedded = False
    
    # Step 3: Look for TestResult
    print("\n--- STEP 3: TestResult Analysis ---")
    test_result = root.find('.//xccdf:TestResult', scan_ns)
    if test_result is None:
        test_result = root.find('.//{http://checklists.nist.gov/xccdf/1.1}TestResult')
    if test_result is None:
        for elem in root.iter():
            if 'TestResult' in elem.tag:
                test_result = elem
                break
    
    if test_result is not None:
        print(f"✓ Found TestResult: {test_result.tag}")
        
        # Look for benchmark reference
        print("\n--- STEP 4: Benchmark Reference Check ---")
        benchmark_elem = test_result.find('.//xccdf:benchmark', scan_ns)
        if benchmark_elem is None:
            # Try lowercase 'benchmark' with namespace
            benchmark_elem = test_result.find('xccdf:benchmark', scan_ns)
        if benchmark_elem is None:
            # Try without namespace
            for child in test_result:
                if 'benchmark' in child.tag.lower():
                    benchmark_elem = child
                    break
        
        if benchmark_elem is not None:
            href = benchmark_elem.get('href', '')
            benchmark_id = benchmark_elem.get('id', '')
            print(f"✓ Found benchmark reference:")
            print(f"  href: {href}")
            print(f"  id: {benchmark_id}")
            print(f"  Tag: {benchmark_elem.tag}")
        else:
            print("✗ No benchmark reference found in TestResult")
            print("  This scan likely has embedded benchmark only")
        
        # Show a few rule-result samples
        print("\n--- STEP 5: Rule Results Sample ---")
        rule_results = test_result.findall('.//xccdf:rule-result', scan_ns)
        if not rule_results:
            rule_results = []
            for elem in test_result.iter():
                if 'rule-result' in elem.tag:
                    rule_results.append(elem)
        
        print(f"Found {len(rule_results)} rule results")
        for i, rr in enumerate(rule_results[:3]):
            rule_id = rr.get('idref', 'unknown')
            result_elem = rr.find('.//xccdf:result', scan_ns)
            if result_elem is None:
                for child in rr:
                    if 'result' in child.tag:
                        result_elem = child
                        break
            result = result_elem.text if result_elem is not None else 'unknown'
            print(f"  {i+1}. Rule: {rule_id} → {result}")
    else:
        print("✗ No TestResult found!")
    
    # Step 6: If external benchmark referenced, simulate loading
    if not embedded and test_result is not None and benchmark_elem is not None and href:
        print("\n--- STEP 6: Simulating External Benchmark Load ---")
        benchmark_filename = os.path.basename(href)
        print(f"Looking for: {benchmark_filename}")
        
        # Check if it would be in cache
        benchmark_dir = os.path.join(os.path.dirname(__file__), "stig_benchmarks")
        
        # Search for the file
        found = False
        for root_dir, dirs, files in os.walk(benchmark_dir):
            if benchmark_filename in files:
                benchmark_path = os.path.join(root_dir, benchmark_filename)
                print(f"✓ Found benchmark file: {benchmark_path}")
                found = True
                
                # Load and check namespace
                try:
                    bm_tree = ET.parse(benchmark_path)
                    bm_root = bm_tree.getroot()
                    print(f"  Benchmark root tag: {bm_root.tag}")
                    
                    if bm_root.tag.startswith('{'):
                        bm_ns_uri = bm_root.tag.split('}')[0][1:]
                        bm_ns = {'xccdf': bm_ns_uri}
                        print(f"  Benchmark namespace: {bm_ns_uri}")
                        
                        if bm_ns_uri == scan_ns_uri:
                            print(f"  ✓ Namespaces MATCH")
                        else:
                            print(f"  ⚠ NAMESPACE MISMATCH!")
                            print(f"    Scan NS:      {scan_ns_uri}")
                            print(f"    Benchmark NS: {bm_ns_uri}")
                            print(f"    → This is OK! Code updates namespace when loading.")
                        
                        # Try to parse with benchmark namespace
                        groups = bm_root.findall('.//xccdf:Group', bm_ns)
                        rules = bm_root.findall('.//xccdf:Rule', bm_ns)
                        print(f"  ✓ Benchmark has {len(groups)} Groups, {len(rules)} Rules")
                        
                        if rules:
                            rule = rules[0]
                            check_elem = rule.find('.//xccdf:check-content', bm_ns)
                            fix_elem = rule.find('.//xccdf:fixtext', bm_ns)
                            check_len = len(check_elem.text) if check_elem is not None and check_elem.text else 0
                            fix_len = len(fix_elem.text) if fix_elem is not None and fix_elem.text else 0
                            print(f"  Sample rule check_content: {check_len} chars")
                            print(f"  Sample rule fix_text: {fix_len} chars")
                            
                            if check_len > 0 and fix_len > 0:
                                print(f"  ✓ Benchmark details can be extracted")
                            else:
                                print(f"  ✗ Benchmark details missing!")
                    
                except Exception as e:
                    print(f"  ✗ Error parsing benchmark: {e}")
                break
        
        if not found:
            print(f"✗ Benchmark file NOT found in stig_benchmarks/")
            print(f"  Parser will create CKLB with limited info")
    
    print("\n")

if __name__ == '__main__':
    # Find all XML files in scan_results
    scan_dir = os.path.join(os.path.dirname(__file__), "scan_results")
    xml_files = glob.glob(os.path.join(scan_dir, "*.xml"))
    
    if not xml_files:
        print("No XML files found in scan_results/")
    else:
        for xml_file in xml_files:
            diagnose_scan_file(xml_file)
