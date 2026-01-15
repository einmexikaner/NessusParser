# Nessus Parser - Quick Start

## What It Does

Converts Nessus XCCDF scan exports → CKLB checklist files for STIG Viewer 3

## Quick Start

1. **Export from Nessus**: Export your scan as XCCDF format
2. **Place file**: Put the `.xml` file in this directory
3. **Run**: `python nessus_parser.py`
4. **Get results**: Find `.cklb` files in the `output/` directory

## Full Documentation

See [NESSUS_MODE_USAGE.md](NESSUS_MODE_USAGE.md) for complete instructions.

## Related Tools

- **nessus_parser.py**: This tool - converts Nessus scans to CKLB
- **offline_stig_checker.py**: Different tool - analyzes device configs against STIG benchmarks

---

**Author**: Fernando Landeros - MARSOC G-631  
**Version**: 1.0  
**Date**: 2026-01-15
