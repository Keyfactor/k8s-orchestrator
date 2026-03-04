#!/usr/bin/env python3
"""
Analyze Cobertura coverage XML to find low-coverage methods and classes.

Usage:
    python3 scripts/analyze-coverage.py [threshold]

Examples:
    python3 scripts/analyze-coverage.py        # Default: find methods below 60%
    python3 scripts/analyze-coverage.py 80     # Find methods below 80%
    python3 scripts/analyze-coverage.py 0      # Show all methods
"""

import xml.etree.ElementTree as ET
import glob
import sys
from pathlib import Path

def analyze_coverage(coverage_dir="./coverage", threshold=60):
    """Find methods below coverage threshold."""

    xml_files = list(glob.glob(f'{coverage_dir}/**/coverage.cobertura.xml', recursive=True))

    if not xml_files:
        print(f"No coverage files found in {coverage_dir}")
        return

    print(f"Analyzing {len(xml_files)} coverage file(s)...")
    print(f"Threshold: {threshold}%\n")

    low_coverage_classes = []

    for xml_file in xml_files:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for package in root.findall('.//package'):
                for cls in package.findall('.//class'):
                    class_name = cls.attrib.get('name', 'Unknown')
                    filename = cls.attrib.get('filename', '')
                    line_rate = float(cls.attrib.get('line-rate', 0)) * 100
                    branch_rate = float(cls.attrib.get('branch-rate', 0)) * 100

                    if line_rate < threshold:
                        methods_info = []
                        for method in cls.findall('.//method'):
                            method_name = method.attrib.get('name', 'Unknown')
                            method_rate = float(method.attrib.get('line-rate', 0)) * 100
                            if method_rate < threshold:
                                methods_info.append((method_name, method_rate))

                        low_coverage_classes.append({
                            'class': class_name,
                            'file': filename,
                            'line_rate': line_rate,
                            'branch_rate': branch_rate,
                            'methods': methods_info
                        })
        except Exception as e:
            print(f"Error parsing {xml_file}: {e}")
            continue

    # Sort by coverage (lowest first)
    low_coverage_classes.sort(key=lambda x: x['line_rate'])

    # Print results
    print(f"{'='*80}")
    print(f"Classes with line coverage below {threshold}%")
    print(f"{'='*80}\n")

    for item in low_coverage_classes:
        print(f"\nClass: {item['class']}")
        print(f"File: {item['file']}")
        print(f"Line coverage: {item['line_rate']:.1f}%")
        print(f"Branch coverage: {item['branch_rate']:.1f}%")

        if item['methods']:
            print("Low-coverage methods:")
            for method_name, rate in sorted(item['methods'], key=lambda x: x[1]):
                print(f"  {rate:5.1f}% - {method_name}")

    # Summary
    print(f"\n{'='*80}")
    print(f"Summary: {len(low_coverage_classes)} classes below {threshold}% coverage")
    print(f"{'='*80}")

    # Top 10 by uncovered lines
    print("\nTop classes to target for improvement (by potential coverage gain):")
    for i, item in enumerate(low_coverage_classes[:10], 1):
        print(f"  {i}. {item['class']} ({item['line_rate']:.1f}%)")

def main():
    threshold = int(sys.argv[1]) if len(sys.argv) > 1 else 60

    # Check for coverage directories
    coverage_dirs = ["./coverage/unit", "./coverage/integration", "./coverage"]

    for cov_dir in coverage_dirs:
        if Path(cov_dir).exists():
            print(f"\n{'#'*80}")
            print(f"# Coverage analysis for: {cov_dir}")
            print(f"{'#'*80}\n")
            analyze_coverage(coverage_dir=cov_dir, threshold=threshold)

if __name__ == '__main__':
    main()
