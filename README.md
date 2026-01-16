# Nessus XCCDF to CKLB Converter

Convert Nessus XCCDF scan exports into CKLB checklist files for STIG Viewer 3.

**Version 1.2** - Organized folder structure with separate directories for benchmarks and scan results!

---

## 🚀 Quick Start

1. **Export from Nessus**: Export your scan as XCCDF format
2. **Place scan file**: Put the scan export `.xml` file in `scan_results/`
3. **(Optional) Add STIG benchmarks**: Place STIG ZIP files in `stig_benchmarks/`
4. **Run**: `python nessus_parser.py`
5. **Get results**: Find `.cklb` files in the `output/` directory

### Example
```powershell
# Your directory structure:
NessusParser/
├── nessus_parser.py
├── scan_results/
│   └── my_scan_results.xml                ← Your Nessus scan export
├── stig_benchmarks/
│   └── U_Cisco_IOS-XE_Router_STIG.zip     ← (Optional) STIG benchmarks
└── output/
    └── hostname_benchmark.cklb            ← Generated CKLB files

# Run the tool:
python nessus_parser.py
```

### Directory Structure

- **`scan_results/`** - Place your Nessus XCCDF scan exports here
- **`stig_benchmarks/`** - Place STIG ZIP files here (for external benchmark references)
- **`output/`** - Generated CKLB files appear here automatically

---

## 📋 Supported Formats

✅ **Nessus XCCDF exports with embedded benchmarks** (all rules in one file)  
✅ **Nessus SCAP exports with external benchmark references** (scan + separate benchmark)  
✅ **Nested ZIP files** (quarterly STIG compilation packages)  
❌ Native `.nessus` files (must be exported as XCCDF)

---

## 🔧 How It Works

### With Embedded Benchmarks
Your Nessus export contains everything needed:
- TestResult data (scan results)
- Benchmark rules (check content, fix text, etc.)

Just drop the file in `scan_results/` and run!

### With External Benchmarks (NEW in v1.1)

When your Nessus SCAP export references an external benchmark:

```xml
<benchmark href="U_Cisco_Router_STIG_V3R3_Manual-xccdf.xml" id="..."/>
```

The parser will:
1. **Load benchmarks** - Automatically extract all XCCDF files from STIG ZIP archives
2. **Match references** - Find the referenced benchmark by filename
3. **Merge data** - Combine scan results with benchmark rule definitions
4. **Generate CKLB** - Create complete checklist with all rule details

**What you need:**
- Your Nessus scan export (contains TestResult)
- The STIG ZIP file from cyber.mil (contains benchmark XCCDF)

**The parser does the rest automatically!**

---

## 📖 Detailed Usage

### Step 1: Export from Nessus

1. Open your Nessus scan with STIG compliance data
2. Click **Export** → **XCCDF**
3. Save the `.xml` file
4. Place it in the `scan_results/` directory

### Step 2: (Optional) Add Benchmark Files

If your scan references external benchmarks, download the STIG ZIP from cyber.mil:

```
https://public.cyber.mil/stigs/downloads/
```

Place the ZIP file(s) in the `stig_benchmarks/` directory. Examples:
- `U_Cisco_IOS-XE_Router_Y25M04_STIG.zip`
- `U_Windows_Server_2022_STIG.zip`
- `U_RHEL_9_STIG.zip`
- Or the entire quarterly compilation ZIP (supports nested ZIPs!)

**The parser automatically extracts all benchmark files from ZIP archives.**

### Step 3: Run the Parser

```powershell
python nessus_parser.py
```

### Step 4: Open in STIG Viewer

1. Download **STIG Viewer 3** from cyber.mil
2. File → Open → Select your `.cklb` file
3. Review and edit findings as needed

---

## 🎯 Status Mapping

Nessus XCCDF statuses → CKLB statuses:

| Nessus Status     | CKLB Status      |
|-------------------|------------------|
| pass              | Not a Finding    |
| fail              | Open             |
| error             | Open             |
| fixed             | Not a Finding    |
| notapplicable     | Not Applicable   |
| notchecked        | Not Reviewed     |
| notselected       | Not Reviewed     |
| unknown           | Not Reviewed     |
| informational     | Not Reviewed     |

---

## 🔍 Benchmark Matching

### How It Works

**Completely generic and adaptable** - works with ANY STIG:
- ✅ Any vendor (Cisco, Windows, Linux, etc.)
- ✅ Any version (V1R1, V3R4, future versions)
- ✅ Multiple STIGs simultaneously
- ✅ No code changes needed for new STIGs

**Matching process:**
1. Parser scans `stig_benchmarks/` directory for `*.zip` files
2. Extracts all `*xccdf.xml` files from ZIPs (including nested ZIPs)
3. Caches them by filename
4. When processing scan: reads `<benchmark href="filename.xml">`
5. Looks up filename in cache
6. Loads matching benchmark

### When Benchmark is Found ✅

```
Processing: cisco_scan.xml
   Found benchmark reference: U_Cisco_IOS-XE_Router_RTR_STIG_V3R3_Manual-xccdf.xml
   Loading benchmark from cache: U_Cisco_IOS-XE_Router_RTR_STIG_V3R3_Manual-xccdf.xml
   Loaded 245 rule definitions from benchmark
   Target: router01 (192.168.1.1)
   STIG: Cisco IOS XE Router RTR Security Technical Implementation Guide
   Results: 245 checks
      85 Open, 145 Not a Finding, 5 Not Applicable, 10 Not Reviewed
   ✅ CKLB written with complete rule details
```

### When Benchmark is NOT Found ⚠️

```
Processing: windows_scan.xml
   Found benchmark reference: U_Windows_Server_2019_STIG.xml
   WARNING: Benchmark file not found: U_Windows_Server_2019_STIG.xml
   Available benchmarks: U_Cisco_IOS-XE_Router_NDM_STIG_V3R4_Manual-xccdf.xml, ...
   HINT: Place the correct STIG ZIP file in stig_benchmarks/ directory
   Will create CKLB with limited rule information from scan data only.
   WARNING: No rule definitions found in benchmark!
   ⚠️ CKLB created with minimal information
```

**What happens:**
- Parser continues processing (doesn't crash)
- Uses whatever data is in the scan export
- CKLB is created but missing:
  - Check content
  - Fix text
  - Detailed descriptions
  - CCI references

**Solution:**
1. Note the expected filename from the WARNING
2. Download the correct STIG ZIP from cyber.mil
3. Place it in the `stig_benchmarks/` directory
4. Re-run the parser

### Best Practices

**Recommended directory structure:**
```
NessusParser/
├── nessus_parser.py
├── scan_results/
│   ├── cisco_scan.xml                      ← Your scan exports
│   └── windows_scan.xml
├── stig_benchmarks/
│   ├── U_Cisco_IOS-XE_Router_STIG.zip      ← STIG benchmarks
│   ├── U_Windows_Server_2019_STIG.zip
│   └── Quarterly_Compilation_2025Q1.zip    ← Or quarterly compilation
└── output/
    └── (generated CKLB files)
```

**Testing your setup:**
```powershell
python nessus_parser.py
```

Look for:
```
1. Loading STIG benchmark files...
   Looking in: c:\..\NessusParser\stig_benchmarks
   Loaded benchmark: U_Cisco_IOS-XE_Router_NDM_STIG_V3R4_Manual-xccdf.xml ✅
   Loaded benchmark: U_Windows_Server_2019_STIG.xml ✅
   Loaded 2 benchmark file(s)

2. Discovering Nessus XCCDF scan export files...
   Looking in: c:\..\NessusParser\scan_results
   Found XCCDF file: cisco_scan.xml
   Found 2 XCCDF file(s)
```

If you see `No benchmark files found`, add STIG ZIPs to `stig_benchmarks/`

---

## 🛠️ Troubleshooting

### "No TestResult found in XCCDF"

**Cause**: File is a STIG benchmark, not a Nessus scan result

**Solution**: Export actual scan results from Nessus, not benchmark files from cyber.mil

---

### "No XCCDF files found"

**Cause**: Files not in the correct location

**Solution**: Place `.xml` scan export files in the `scan_results/` directory

---

### "Benchmark file not found"

**Cause**: Referenced benchmark not in directory or filename mismatch

**Solution**: 
1. Check the WARNING message for expected filename
2. Download correct STIG ZIP from cyber.mil
3. Place in `stig_benchmarks/` directory
4. Re-run

---

### CKLB missing check content or fix text

**Cause**: Processed without benchmark file

**Solution**: Add the referenced STIG ZIP to `stig_benchmarks/` and re-run

---

### Empty or minimal data in CKLB

**Cause**: No benchmark definitions loaded

**Solution**: 
- Ensure STIG ZIP files are in `stig_benchmarks/` directory
- Check that ZIP files contain `*xccdf.xml` files
- Verify filenames match the references in your scan export
- Try the quarterly compilation ZIP (supports nested ZIPs)

---

## 📊 Example Output

```powershell
PS C:\NessusParser> python nessus_parser.py

================================================================================
Nessus XCCDF to CKLB Converter
================================================================================

1. Loading STIG benchmark files...
   Looking in: C:\NessusParser\stig_benchmarks
   Loaded benchmark: U_Cisco_IOS-XE_Router_NDM_STIG_V3R4_Manual-xccdf.xml
   Loaded benchmark: U_Cisco_IOS-XE_Router_RTR_STIG_V3R3_Manual-xccdf.xml
   Loaded 2 benchmark file(s)

2. Discovering Nessus XCCDF scan export files...
   Looking in: C:\NessusParser\scan_results
   Found XCCDF file: router01_scan.xml
   Found 1 XCCDF file(s)

3. Processing Nessus XCCDF files...

   Processing: router01_scan.xml
      Found benchmark reference: U_Cisco_IOS-XE_Router_RTR_STIG_V3R3_Manual-xccdf.xml
      Loading benchmark from cache: U_Cisco_IOS-XE_Router_RTR_STIG_V3R3_Manual-xccdf.xml
      Loaded 245 rule definitions from benchmark
      Target: router01 (192.168.1.1)
      STIG: Cisco IOS XE Router RTR Security Technical Implementation Guide
      Results: 245 checks
         85 Open, 145 Not a Finding, 5 Not Applicable, 10 Not Reviewed
         CKLB written: output\router01_U_Cisco_IOS-XE_Router_RTR_STIG.cklb

================================================================================
SUMMARY
================================================================================
Files processed: 1
Files skipped/errors: 0
Output location: C:\NessusParser\output
================================================================================

Next steps:
1. Open STIG Viewer 3
2. File → Open → Select your .cklb file
3. Review and edit findings as needed
================================================================================
```

---

##  Requirements

- Python 3.6 or higher
- No additional packages required (uses standard library only)
- Nessus XCCDF export files
- (Optional) STIG benchmark ZIP files for external references

---

---

## 🎓 Additional Notes

### Future-Proofing

This design is completely adaptable:
- ✅ Works with new STIG versions (just download new ZIP)
- ✅ Works with different scanners (any XCCDF with TestResult)
- ✅ Handles multiple STIGs simultaneously
- ✅ Supports custom/organization-specific benchmarks
- ✅ No code changes needed for future STIGs

### Technical Details

- Parses XCCDF 1.1 and 1.2 namespaces automatically
- Handles both relative and absolute benchmark references
- Case-sensitive filename matching
- Graceful degradation when benchmarks are missing
- Preserves all scan metadata (hostname, IP, timestamps)
