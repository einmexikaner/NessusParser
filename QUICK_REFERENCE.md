# Quick Reference Card

## 📂 Directory Structure

```
NessusParser/
├── nessus_parser.py           ← The tool
├── scan_results/              ← PUT NESSUS SCANS HERE
│   └── your_scan.xml
├── stig_benchmarks/           ← PUT STIG ZIPS HERE
│   └── STIG_Package.zip
└── output/                    ← CKLB FILES APPEAR HERE
    └── generated.cklb
```

## ⚡ Quick Start

1. **Export from Nessus** → XCCDF format
2. **Place scan** → `scan_results/your_scan.xml`
3. **(Optional) Place STIG ZIPs** → `stig_benchmarks/`
4. **Run** → `python nessus_parser.py`
5. **Get CKLB** → `output/`

## 🎯 What Goes Where

| File Type | Location |
|-----------|----------|
| Nessus scan export (XML) | `scan_results/` |
| STIG benchmark ZIP | `stig_benchmarks/` |
| Quarterly compilation ZIP | `stig_benchmarks/` (nested ZIPs supported!) |
| Generated CKLB files | `output/` (automatic) |

## ✅ Supported

- ✅ Embedded benchmarks (all-in-one XCCDF)
- ✅ External benchmark references
- ✅ Nested ZIP files (quarterly compilation)
- ✅ Multiple STIGs
- ✅ Any STIG vendor/version

## ❌ Not Supported

- ❌ Native `.nessus` files (must export as XCCDF)

## 🔧 Common Issues

| Issue | Solution |
|-------|----------|
| "No XCCDF files found" | Put scan XML files in `scan_results/` |
| "Benchmark file not found" | Put STIG ZIP in `stig_benchmarks/` |
| "No TestResult found" | You have a benchmark, not a scan export |
| Missing check content | Add benchmark ZIP to `stig_benchmarks/` |

## 📋 Example Output

```
1. Loading STIG benchmark files...
   Looking in: C:\...\stig_benchmarks
   Loaded 2 benchmark file(s)

2. Discovering Nessus XCCDF scan export files...
   Looking in: C:\...\scan_results
   Found 1 XCCDF file(s)

3. Processing Nessus XCCDF files...
   Processing: router_scan.xml
      Loaded 245 rule definitions from benchmark
      ✅ CKLB written: output\router_benchmark.cklb
```

## 🚀 Next Steps

1. Open STIG Viewer 3
2. File → Open → Select `.cklb` from `output/`
3. Review and edit findings

---

**Version 1.2** | Fernando Landeros - MARSOC G-631
