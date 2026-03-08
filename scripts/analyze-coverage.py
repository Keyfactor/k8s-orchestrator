#!/usr/bin/env python3
"""
Analyze Cobertura coverage XML to find low-coverage methods and classes.

Usage:
    python3 scripts/analyze-coverage.py [threshold]
    python3 scripts/analyze-coverage.py --class CertificateUtilities
    python3 scripts/analyze-coverage.py --summary
    python3 scripts/analyze-coverage.py --uncovered CertificateUtilities

Examples:
    python3 scripts/analyze-coverage.py        # Default: find methods below 60%
    python3 scripts/analyze-coverage.py 80     # Find methods below 80%
    python3 scripts/analyze-coverage.py 0      # Show all methods
"""

import xml.etree.ElementTree as ET
import glob
import sys
from pathlib import Path


def find_xml_files(coverage_dir="./coverage"):
    """Find coverage XML files."""
    return list(glob.glob(f'{coverage_dir}/**/coverage.cobertura.xml', recursive=True))


def analyze_coverage(coverage_dir="./coverage", threshold=60):
    """Find methods below coverage threshold."""

    xml_files = find_xml_files(coverage_dir)

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


def show_uncovered(coverage_dir, class_filter):
    """Show uncovered lines for a specific class."""
    for f in find_xml_files(coverage_dir):
        tree = ET.parse(f)
        root = tree.getroot()

        seen = set()
        for cls in root.findall('.//class'):
            class_name = cls.attrib.get('name', '')
            if class_name in seen:
                continue
            seen.add(class_name)

            if class_filter.lower() not in class_name.lower():
                continue

            lines = cls.findall('.//line')
            if not lines:
                continue

            covered = sum(1 for l in lines if int(l.attrib.get('hits', 0)) > 0)
            uncovered = sum(1 for l in lines if l.attrib.get('hits', '0') == '0')
            total = covered + uncovered
            if total == 0:
                continue

            rate = 100 * covered / total
            short_name = class_name.split('.')[-1]
            print(f'\n{short_name}: {covered}/{total} ({rate:.1f}%) - {uncovered} uncovered')
            print('Uncovered lines:')
            for line in lines:
                if line.attrib.get('hits', '0') == '0':
                    print(f'  Line {line.attrib["number"]}')
        break  # Only first file


def show_summary(coverage_dir):
    """Show all classes sorted by uncovered line count."""
    for f in find_xml_files(coverage_dir):
        tree = ET.parse(f)
        root = tree.getroot()

        results = []
        seen = set()
        for cls in root.findall('.//class'):
            class_name = cls.attrib.get('name', '')
            if class_name in seen:
                continue
            seen.add(class_name)

            lines = cls.findall('.//line')
            if not lines:
                continue

            covered = sum(1 for l in lines if int(l.attrib.get('hits', 0)) > 0)
            uncovered = sum(1 for l in lines if l.attrib.get('hits', '0') == '0')
            total = covered + uncovered
            if total == 0:
                continue

            rate = 100 * covered / total
            short_name = class_name.split('.')[-1]
            results.append((uncovered, rate, short_name, covered, total))

        results.sort(key=lambda x: -x[0])
        print(f'\n{"Class":<45} {"Covered":>8} {"Total":>6} {"Rate":>7} {"Uncov":>6}')
        print('-' * 75)
        for uncov, rate, name, cov, total in results:
            if uncov > 0:
                print(f'{name:<45} {cov:>8} {total:>6} {rate:>6.1f}% {uncov:>6}')
        break


def resolve_dir(explicit_dir=None):
    """Resolve coverage directory, preferring explicit --dir, then auto-detect."""
    if explicit_dir:
        return explicit_dir
    for d in ["./coverage/unit", "./coverage", "./coverage/integration"]:
        if Path(d).exists() and find_xml_files(d):
            return d
    return "./coverage"


def get_flag_value(flag):
    """Get the value after a flag, or None."""
    if flag in sys.argv:
        idx = sys.argv.index(flag)
        if idx + 1 < len(sys.argv) and not sys.argv[idx + 1].startswith('-'):
            return sys.argv[idx + 1]
        return ''
    return None


def main():
    explicit_dir = get_flag_value('--dir')
    cov_dir = resolve_dir(explicit_dir)

    # Check for --summary, --uncovered, or --class flags
    if '--summary' in sys.argv:
        print(f"\n# {cov_dir}")
        show_summary(cov_dir)
        return

    class_filter = get_flag_value('--uncovered') or get_flag_value('--class')
    if class_filter is not None:
        show_uncovered(cov_dir, class_filter)
        return
        return

    threshold = int(sys.argv[1]) if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else 60

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
