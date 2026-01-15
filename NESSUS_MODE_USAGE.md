# Nessus XCCDF to CKLB Converter - Usage Guide

## Overview

The `nessus_parser.py` tool converts Nessus XCCDF scan exports directly into CKLB checklist files for STIG Viewer 3.

**Note**: This is a separate tool from `offline_stig_checker.py`, which analyzes device configurations.

## Prerequisites

1. **Nessus XCCDF Export**: You need an XCCDF export from Nessus Scanner
   - In Nessus, export your scan results as "XCCDF" format
   - The file must contain `<TestResult>` data (actual scan results)
   - Standard STIG benchmark files from cyber.mil will NOT work in Nessus mode

2. **Python 3.6+**: No additional packages required (uses standard library)

## How to Use

### Step 1: Export from Nessus

1. Open your Nessus scan that has STIG compliance data
2. Click **Export** → **XCCDF**
3. Save the `.xml` file to your computer

### Step 2: Place Files

Place your Nessus XCCDF export files in the same directory as `nessus_parser.py`

```
Offline Config Checker/
├── offline_stig_checker.py   ← Config analysis tool
├── nessus_parser.py           ← Nessus converter tool
├── your_nessus_scan.xml       ← Place Nessus XCCDF here
└── output/                    ← CKLB files go here
```

### Step 3: Run the Tool

Open PowerShell or Command Prompt and run:

```powershell
python nessus_parser.py
```

### Step 4: Get Your CKLB Files

The tool will:
- Parse each Nessus XCCDF file
- Extract the target hostname, IP, and scan results
- Convert each finding status to CKLB format
- Generate `.cklb` files in the `output/` directory

Output example:
```
output/
├── server01_U_Cisco_IOS_XE_Switch_NDM_V2R7.cklb
└── server02_U_Windows_Server_2022_V1R3.cklb
```

## Status Mapping

Nessus XCCDF statuses are automatically mapped to CKLB statuses:

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

## Opening CKLB Files

1. Download **STIG Viewer 3** from cyber.mil
2. Open STIG Viewer
3. File → Open → Select your `.cklb` file
4. Review and edit findings as needed
5. Export as needed for submission

## Troubleshooting

### "No TestResult found in XCCDF"

**Cause**: The file is a STIG benchmark, not a Nessus scan result

**Solution**: Make sure you're exporting actual scan results from Nessus, not downloading benchmark files from cyber.mil

### "No XCCDF files found"

**Cause**: Files not in the correct location

**Solution**: Place `.xml` files in the same directory as the script

### Empty or missing data in CKLB

**Cause**: Nessus XCCDF may not include all STIG metadata

**Solution**: This is normal - you may need to manually add comments/details in STIG Viewer

## Comparison: Config Mode vs Nessus Mode

| Feature                    | Config Mode (Default) | Nessus Mode (--nessus) |
|----------------------------|-----------------------|------------------------|
| Input Files                | STIG benchmark XCCDF + device configs | Nessus XCCDF scan results |
| Analysis     Two Separate Tools

| Feature                    | offline_stig_checker.py | nessus_parser.py |
|----------------------------|-----------------------|------------------------|
| Purpose                    | Analyze device configs | Convert Nessus scans 
| Use case                   | Offline config analysis | Convert existing Nessus scans |

## Example Workflow

```powershell
# Run the Nessus converter
python nessus_parser.py

# Output:
# ================================================================================
# Nessus XCCDF to CKLB Converter
# ================================================================================
#
# 1. Discovering Nessus XCCDF files...
# Found 1 XCCDF file(s)
#
# 2. Processing Nessus XCCDF files...
#
#    Processing: server01_stig_scan.xml
#       Target: server01 (192.168.1.100)
#       STIG: U_Cisco_IOS_XE_Switch_NDM_STIG
#       Results: 156 checks
#          45 Open, 98 Not a Finding, 5 Not Applicable, 8 Not Reviewed
#          CKLB written: output\server01_U_Cisco_IOS_XE_Switch_NDM_V2R7.cklb
#
# ================================================================================
# SUMMARY
# ================================================================================
# Files processed: 1
# Files skipped/errors: 0
# Output location: C:\...\output
# ================================================================================
```

## Support

For the offline config checker tool, see `README_offline.md`

For questions or issues, contact Fernando Landeros - MARSOC G-631
