#!/usr/bin/env python3
"""
Nessus XCCDF to CKLB Converter

This script converts Nessus XCCDF scan exports into CKLB checklist files
compatible with STIG Viewer 3.

Features:
- Supports embedded benchmarks (all-in-one XCCDF files)
- Supports external benchmark references (loads from STIG ZIP files)
- Automatically matches benchmark files by href attribute
- Supports nested ZIP files (quarterly STIG compilation packages)
- Organized folder structure (scan_results/ and stig_benchmarks/)

Directory Structure:
- scan_results/     - Place Nessus XCCDF scan exports here
- stig_benchmarks/  - Place STIG ZIP files here (including quarterly compilation)
- output/           - Generated CKLB files appear here

Usage:
1. Place Nessus scan exports in scan_results/
2. (Optional) Place STIG benchmark ZIPs in stig_benchmarks/
3. Run: python nessus_parser.py
4. Find CKLB files in output/

Requirements:
- Python 3.6+
- Nessus XCCDF export files (must contain TestResult data)
- (Optional) STIG benchmark ZIP files for external references

Author: Fernando Landeros - MARSOC G-631
Version: 1.2 - Organized Folder Structure & Enhanced TestResult Detection
Version date: 2026-01-16
"""

import os
import json
import glob
from datetime import datetime
import xml.etree.ElementTree as ET
import zipfile

# --- CONFIGURATION ---
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
BENCHMARK_DIR = os.path.join(os.path.dirname(__file__), "stig_benchmarks")
SCAN_RESULTS_DIR = os.path.join(os.path.dirname(__file__), "scan_results")
BENCHMARK_CACHE = {}  # Cache for loaded benchmark files

# --- FUNCTIONS ---

def load_benchmark_files():
    """
    Load all benchmark XCCDF files from ZIP archives and loose files.
    Looks in the stig_benchmarks/ directory for STIG packages.
    Stores them in BENCHMARK_CACHE for later reference.
    Supports nested ZIP files (ZIP inside ZIP).
    """
    global BENCHMARK_CACHE
    
    # Create benchmark directory if it doesn't exist
    os.makedirs(BENCHMARK_DIR, exist_ok=True)
    
    # Check for benchmark files in ZIP archives in the benchmark directory
    zip_pattern = os.path.join(BENCHMARK_DIR, "*.zip")
    for zip_file in glob.glob(zip_pattern):
        try:
            with zipfile.ZipFile(zip_file, 'r') as z:
                    for name in z.namelist():
                        # Handle XCCDF XML files directly in the ZIP
                        if name.endswith('xccdf.xml') or (name.endswith('.xml') and 'xccdf' in name.lower()):
                            filename = os.path.basename(name)
                            BENCHMARK_CACHE[filename] = z.read(name)
                            print(f"   Loaded benchmark: {filename}")
                        
                        # Handle nested ZIP files
                        elif name.endswith('.zip'):
                            try:
                                # Read the nested ZIP into memory
                                nested_zip_data = z.read(name)
                                # Open it as a ZIP file from memory
                                import io
                                with zipfile.ZipFile(io.BytesIO(nested_zip_data), 'r') as nested_z:
                                    for nested_name in nested_z.namelist():
                                        if nested_name.endswith('xccdf.xml') or (nested_name.endswith('.xml') and 'xccdf' in nested_name.lower()):
                                            filename = os.path.basename(nested_name)
                                            BENCHMARK_CACHE[filename] = nested_z.read(nested_name)
                                            print(f"   Loaded benchmark from nested ZIP: {filename}")
                            except Exception as nested_error:
                                # Skip if nested ZIP is corrupt or not a valid ZIP
                                pass
        except Exception as e:
            print(f"   Error loading benchmarks from {zip_file}: {e}")
    
    # Check for loose benchmark XML files in the benchmark directory and subdirectories
    xml_pattern = os.path.join(BENCHMARK_DIR, "*xccdf*.xml")
    for xml_file in glob.glob(xml_pattern):
        try:
            with open(xml_file, 'rb') as f:
                content = f.read()
                filename = os.path.basename(xml_file)
                BENCHMARK_CACHE[filename] = content
                print(f"   Loaded benchmark: {filename}")
        except Exception as e:
            print(f"   Error loading {xml_file}: {e}")
    
    # Also search in subdirectories
    xml_pattern_recursive = os.path.join(BENCHMARK_DIR, "**", "*xccdf*.xml")
    for xml_file in glob.glob(xml_pattern_recursive, recursive=True):
        filename = os.path.basename(xml_file)
        if filename not in BENCHMARK_CACHE:  # Don't override already loaded files
            try:
                with open(xml_file, 'rb') as f:
                    content = f.read()
                    BENCHMARK_CACHE[filename] = content
                    print(f"   Loaded benchmark from subdirectory: {filename}")
            except Exception as e:
                print(f"   Error loading {xml_file}: {e}")

def discover_xccdf_files():
    """
    Discover all XCCDF scan result files in the scan_results/ directory.
    Checks for loose .xml files and extracts from .zip files.
    Returns list of tuples: (filename, xml_content_bytes)
    """
    xccdf_files = []
    
    # Create scan results directory if it doesn't exist
    os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)
    
    # Check for loose XCCDF XML files in scan_results directory
    xml_pattern = os.path.join(SCAN_RESULTS_DIR, "*.xml")
    for xml_file in glob.glob(xml_pattern):
        print(f"Found XCCDF file: {os.path.basename(xml_file)}")
        with open(xml_file, 'rb') as f:
            content = f.read()
            xccdf_files.append((os.path.basename(xml_file), content))
    
    # Check for XCCDF files in ZIP archives in scan_results directory
    zip_pattern = os.path.join(SCAN_RESULTS_DIR, "*.zip")
    for zip_file in glob.glob(zip_pattern):
        print(f"Checking ZIP file: {os.path.basename(zip_file)}")
        try:
            with zipfile.ZipFile(zip_file, 'r') as z:
                for name in z.namelist():
                    if name.endswith('.xml'):
                        xccdf_files.append((os.path.basename(name), z.read(name)))
        except Exception as e:
            print(f"Error processing {zip_file}: {e}")
    
    return xccdf_files

def parse_nessus_xccdf_results(xccdf_bytes, benchmark_bytes=None):
    """
    Parse Nessus XCCDF export containing TestResult data.
    If benchmark_bytes is provided, uses that for rule definitions.
    Otherwise, looks for embedded benchmark or tries to load from external reference.
    Returns: (target_info, stig_info, results_list)
    """
    root = ET.fromstring(xccdf_bytes)
    
    # Handle XCCDF namespace - support both 1.1 and 1.2
    ns = {'xccdf': 'http://checklists.nist.gov/xccdf/1.1'}  # Default to 1.1
    if root.tag.startswith('{'):
        ns_uri = root.tag.split('}')[0][1:]
        ns = {'xccdf': ns_uri}
        # Also try both 1.1 and 1.2 namespaces as fallback
        if '1.2' in ns_uri:
            print("      Detected XCCDF 1.2 format")
        elif '1.1' in ns_uri:
            print("      Detected XCCDF 1.1 format")
    
    # Try to find embedded benchmark first
    benchmark = root.find('.//xccdf:Benchmark', ns)
    
    # If no embedded benchmark, check for external reference
    if benchmark is None or len(benchmark.findall('.//xccdf:Group', ns)) == 0:
        print("      No embedded benchmark found, checking for external reference...")
        
        # Look for benchmark reference in TestResult
        # If root IS TestResult, use it directly, otherwise search for it
        if 'TestResult' in root.tag:
            test_result = root
        else:
            test_result = root.find('.//xccdf:TestResult', ns)
        
        if test_result is not None:
            # Try to find benchmark element (could be 'benchmark' or 'Benchmark')
            benchmark_elem = test_result.find('.//xccdf:benchmark', ns)
            if benchmark_elem is None:
                benchmark_elem = test_result.find('xccdf:benchmark', ns)
            if benchmark_elem is not None:
                benchmark_href = benchmark_elem.get('href', '')
                if benchmark_href:
                    print(f"      Found benchmark reference: {benchmark_href}")
                    # Try to load from cache
                    benchmark_filename = os.path.basename(benchmark_href)
                    if benchmark_filename in BENCHMARK_CACHE:
                        print(f"      Loading benchmark from cache: {benchmark_filename}")
                        benchmark_root = ET.fromstring(BENCHMARK_CACHE[benchmark_filename])
                        
                        # Update namespace to match the benchmark file
                        if benchmark_root.tag.startswith('{'):
                            benchmark_ns_uri = benchmark_root.tag.split('}')[0][1:]
                            ns = {'xccdf': benchmark_ns_uri}
                        
                        benchmark = benchmark_root.find('.//xccdf:Benchmark', ns) or benchmark_root
                    else:
                        print(f"      WARNING: Benchmark file not found: {benchmark_filename}")
                        if BENCHMARK_CACHE:
                            print(f"      Available benchmarks: {', '.join(BENCHMARK_CACHE.keys())}")
                            print(f"      HINT: Place the correct STIG ZIP file in stig_benchmarks/ directory")
                        else:
                            print(f"      No benchmark files loaded. Place STIG ZIP files in stig_benchmarks/")
                        print(f"      Will create CKLB with limited rule information from scan data only.")
        
        # If still no benchmark and external benchmark provided, use it
        if (benchmark is None or len(benchmark.findall('.//xccdf:Group', ns)) == 0) and benchmark_bytes:
            print("      Using provided external benchmark...")
            benchmark_root = ET.fromstring(benchmark_bytes)
            
            # Update namespace to match the benchmark file
            if benchmark_root.tag.startswith('{'):
                benchmark_ns_uri = benchmark_root.tag.split('}')[0][1:]
                ns = {'xccdf': benchmark_ns_uri}
            
            benchmark = benchmark_root.find('.//xccdf:Benchmark', ns) or benchmark_root
    
    # Fallback to root if still no benchmark
    if benchmark is None:
        benchmark = root
    
    stig_id = benchmark.get('id', 'Unknown_STIG')
    stig_title = benchmark.findtext('xccdf:title', stig_id, ns)
    
    # Find TestResult section (contains actual scan results from Nessus)
    # If root IS TestResult, use it directly
    if 'TestResult' in root.tag:
        test_result = root
    else:
        # Try multiple methods to find TestResult
        test_result = root.find('.//xccdf:TestResult', ns)
        if test_result is None:
            # Try both XCCDF 1.1 and 1.2 namespaces
            test_result = root.find('.//{http://checklists.nist.gov/xccdf/1.1}TestResult')
        if test_result is None:
            test_result = root.find('.//{http://checklists.nist.gov/xccdf/1.2}TestResult')
        if test_result is None:
            # Try direct child search
            test_result = root.find('xccdf:TestResult', ns)
        if test_result is None:
            # Last resort - look for any element with TestResult in the tag
            for elem in root.iter():
                if 'TestResult' in elem.tag:
                    test_result = elem
                    break
    
    if test_result is None:
        raise ValueError("No TestResult found in XCCDF - this may not be a Nessus scan export")
    
    # Extract target information
    target_info = {
        'hostname': test_result.findtext('.//xccdf:target', 'Unknown_Host', ns),
        'ip_address': test_result.findtext('.//xccdf:target-address', '', ns),
        'start_time': test_result.get('start-time', ''),
        'end_time': test_result.get('end-time', '')
    }
    
    # Parse all rule results
    results = []
    rule_results = test_result.findall('.//xccdf:rule-result', ns)
    
    # Map Nessus/XCCDF statuses to CKLB statuses
    status_map = {
        'pass': 'not_a_finding',
        'fail': 'open',
        'error': 'open',
        'unknown': 'not_reviewed',
        'notapplicable': 'not_applicable',
        'notchecked': 'not_reviewed',
        'notselected': 'not_reviewed',
        'informational': 'not_reviewed',
        'fixed': 'not_a_finding'
    }
    
    # Build a map of rule definitions from the benchmark
    rule_definitions = {}
    for group in benchmark.findall('.//xccdf:Group', ns):
        group_id = group.get('id', '')
        group_title = group.findtext('xccdf:title', '', ns)
        
        for rule in group.findall('.//xccdf:Rule', ns):
            rule_id = rule.get('id', '')
            
            # Extract rule details
            rule_definitions[rule_id] = {
                'rule_id': rule_id,
                'group_id': group_id,
                'vuln_id': group_id,
                'group_title': group_title,
                'rule_title': rule.findtext('xccdf:title', '', ns),
                'severity': rule.get('severity', 'medium'),
                'description': rule.findtext('xccdf:description', '', ns),
                'version': rule.findtext('.//xccdf:version', '', ns),
                'check_content': '',
                'fix_text': '',
                'cci_ref': ''
            }
            
            # Extract check content
            check_elem = rule.find('.//xccdf:check', ns)
            if check_elem is not None:
                check_content_elem = check_elem.find('.//xccdf:check-content', ns)
                if check_content_elem is not None:
                    rule_definitions[rule_id]['check_content'] = check_content_elem.text or ""
            
            # Extract fix text
            fix_elem = rule.find('.//xccdf:fixtext', ns)
            if fix_elem is not None:
                rule_definitions[rule_id]['fix_text'] = fix_elem.text or ""
            
            # Extract CCI references
            cci_refs = []
            for ident in rule.findall('.//xccdf:ident', ns):
                if ident.get('system') and 'cci' in ident.get('system', '').lower():
                    cci_refs.append(ident.text or "")
            rule_definitions[rule_id]['cci_ref'] = ", ".join(cci_refs) if cci_refs else ""
    
    # Report benchmark loading status
    if not rule_definitions:
        print(f"      WARNING: No rule definitions found in benchmark!")
        print(f"      CKLB will be created with minimal information from scan results only.")
    else:
        print(f"      Loaded {len(rule_definitions)} rule definitions from benchmark")
    
    # Process each rule result from the scan
    for rule_result in rule_results:
        rule_idref = rule_result.get('idref', '')
        result_status = rule_result.findtext('xccdf:result', 'unknown', ns).lower()
        
        # Get rule definition
        rule_def = rule_definitions.get(rule_idref, {
            'rule_id': rule_idref,
            'vuln_id': rule_idref,
            'group_id': rule_idref,
            'group_title': '',
            'rule_title': rule_idref,
            'severity': 'medium',
            'description': '',
            'check_content': '',
            'fix_text': '',
            'version': '',
            'cci_ref': ''
        })
        
        # Map to CKLB status
        cklb_status = status_map.get(result_status, 'not_reviewed')
        
        # Extract finding details and comments from check content
        finding_details = ""
        comments = ""
        
        check_elem = rule_result.find('.//xccdf:check', ns)
        if check_elem is not None:
            check_content_ref = check_elem.find('.//xccdf:check-content-ref', ns)
            if check_content_ref is not None:
                finding_details = f"Check performed: {check_content_ref.get('name', '')}"
        
        # Look for message elements
        message_elem = rule_result.find('.//xccdf:message', ns)
        if message_elem is not None and message_elem.text:
            comments = message_elem.text
        
        # Build result object
        result = {
            'rule_id': rule_def['rule_id'],
            'vuln_id': rule_def['vuln_id'],
            'group_id': rule_def['group_id'],
            'group_title': rule_def['group_title'],
            'rule_title': rule_def['rule_title'],
            'severity': rule_def['severity'],
            'description': rule_def['description'],
            'check_content': rule_def['check_content'],
            'fix_text': rule_def['fix_text'],
            'rule_ver': rule_def['version'],
            'cci_ref': rule_def['cci_ref'],
            'status': cklb_status,
            'finding_details': finding_details,
            'comments': comments,
            'nessus_result': result_status  # Keep original for reference
        }
        
        results.append(result)
    
    stig_info = {
        'stig_id': stig_id,
        'title': stig_title
    }
    
    return target_info, stig_info, results

def generate_cklb(hostname, stig_id, stig_title, results):
    """Generate CKLB file compatible with STIG Viewer 3 (JSON format)"""
    # STIG Viewer 3 uses JSON format for .cklb files, not XML
    
    # Build the JSON structure for STIG Viewer 3
    cklb_data = {
        "target_data": {
            "target_type": "Computing",
            "host_name": str(hostname),
            "ip_address": "",
            "mac_address": "",
            "fqdn": str(hostname),
            "tech_area": "",
            "target_comment": "",
            "web_or_database": False,
            "web_db_site": "",
            "web_db_instance": "",
            "classification": None
        },
        "stigs": [
            {
                "stig_name": str(stig_title),
                "display_name": str(stig_title),
                "stig_id": str(stig_id),
                "version": 1,
                "release_info": "Release: 4 Benchmark Date: 25 Apr 2025",
                "uuid": "",
                "reference_identifier": "",
                "size": len(results),
                "rules": []
            }
        ],
        "cklb_version": "1.0",
        "active": False,
        "mode": 1,
        "title": f"{hostname}_{stig_id}",
        "has_path": True
    }
    
    # Process vulnerabilities into JSON format for STIG Viewer 3
    for result in results:
        # Helper function to safely get text
        def safe_text(value):
            if value is None:
                return ""
            return str(value).strip()
        
        # Build the rule object for JSON
        rule_data = {
            "uuid": "",
            "vuln_num": safe_text(result.get("vuln_id", "")),
            "severity": safe_text(result.get("severity", "medium")).lower(),
            "group_title": safe_text(result.get("rule_title", "")),
            "rule_id": safe_text(result.get("rule_id", "")),
            "rule_ver": safe_text(result.get("rule_ver") or "1"),
            "rule_title": safe_text(result.get("rule_title", "")),
            "vuln_discuss": safe_text(result.get("description", "")),
            "ia_controls": "",
            "check_content": safe_text(result.get("check_content", "")),
            "fix_text": safe_text(result.get("fix_text", "")),
            "false_positives": "",
            "false_negatives": "",
            "documentable": False,
            "mitigations": "",
            "potential_impact": "",
            "third_party_tools": "",
            "mitigation_control": "",
            "responsibility": "",
            "security_override_guidance": "",
            "cci_ref": safe_text(result.get("cci_ref", "")),
            "status": safe_text(result.get("status", "not_reviewed")),
            "finding_details": safe_text(result.get("finding_details", "")),
            "comments": safe_text(result.get("comments", "")),
            "severity_override": "",
            "severity_justification": "",
            "rule_id_src": safe_text(result.get("rule_id", "")),
            "overrides": {}
        }
        
        # Add the rule to the STIG
        cklb_data["stigs"][0]["rules"].append(rule_data)
    
    # Return formatted JSON
    return json.dumps(cklb_data, indent=2, ensure_ascii=False)

# --- MAIN SCRIPT ---

def main():
    """
    Nessus XCCDF to CKLB Converter
    Processes Nessus XCCDF exports and generates CKLB files
    """
    print("=" * 80)
    print("Nessus XCCDF to CKLB Converter")
    print("=" * 80)
    
    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Load benchmark files first
    print("\n1. Loading STIG benchmark files...")
    print(f"   Looking in: {BENCHMARK_DIR}")
    load_benchmark_files()
    if BENCHMARK_CACHE:
        print(f"   Loaded {len(BENCHMARK_CACHE)} benchmark file(s)")
    else:
        print("   No benchmark files found")
        print(f"   Place STIG ZIP files in: {BENCHMARK_DIR}")
        print("   Will attempt to use embedded benchmarks from scan exports")
    
    # Discover all XCCDF files
    print("\n2. Discovering Nessus XCCDF scan export files...")
    print(f"   Looking in: {SCAN_RESULTS_DIR}")
    xccdf_files = discover_xccdf_files()
    
    if not xccdf_files:
        print(f"ERROR: No XCCDF files found in {SCAN_RESULTS_DIR}")
        print(f"Please place Nessus XCCDF export files in: {SCAN_RESULTS_DIR}")
        return
    
    print(f"Found {len(xccdf_files)} XCCDF file(s)")
    
    # Process each XCCDF file
    print("\n3. Processing Nessus XCCDF files...")
    processed_count = 0
    error_count = 0
    
    for filename, xml_content in xccdf_files:
        print(f"\n   Processing: {filename}")
        
        try:
            # Parse Nessus XCCDF results
            target_info, stig_info, results = parse_nessus_xccdf_results(xml_content)
            
            hostname = target_info['hostname']
            ip_address = target_info['ip_address']
            
            print(f"      Target: {hostname} ({ip_address})")
            print(f"      STIG: {stig_info['title']}")
            print(f"      Results: {len(results)} checks")
            
            # Count findings
            open_findings = sum(1 for r in results if r['status'] == 'open')
            not_a_finding = sum(1 for r in results if r['status'] == 'not_a_finding')
            not_applicable = sum(1 for r in results if r['status'] == 'not_applicable')
            not_reviewed = sum(1 for r in results if r['status'] == 'not_reviewed')
            
            print(f"         {open_findings} Open, {not_a_finding} Not a Finding, {not_applicable} Not Applicable, {not_reviewed} Not Reviewed")
            
            # Generate CKLB file
            cklb_json = generate_cklb(hostname, stig_info['stig_id'], stig_info['title'], results)
            
            # Clean filename
            safe_hostname = "".join(c for c in hostname if c.isalnum() or c in ('-', '_')).rstrip()
            safe_stig_id = "".join(c for c in stig_info['stig_id'] if c.isalnum() or c in ('-', '_')).rstrip()
            
            cklb_filename = os.path.join(OUTPUT_DIR, f"{safe_hostname}_{safe_stig_id}.cklb")
            
            with open(cklb_filename, "w", encoding='utf-8') as f:
                f.write(cklb_json)
            
            print(f"         CKLB written: {cklb_filename}")
            processed_count += 1
            
        except ValueError as ve:
            print(f"      SKIPPED: {ve}")
            print(f"      This file may be a STIG benchmark, not a scan result.")
            error_count += 1
        except Exception as e:
            print(f"      ERROR: {e}")
            import traceback
            traceback.print_exc()
            error_count += 1
    
    # Print summary
    print(f"\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Files processed: {processed_count}")
    print(f"Files skipped/errors: {error_count}")
    print(f"Output location: {os.path.abspath(OUTPUT_DIR)}")
    print("=" * 80)
    print("\nNext steps:")
    print("1. Open STIG Viewer 3")
    print("2. File → Open → Select your .cklb file")
    print("3. Review and edit findings as needed")
    print("=" * 80)

if __name__ == "__main__":
    main()
