#!/usr/bin/env python3
"""
Boundary Daemon Report Generator CLI

Generates monitoring reports and optionally sends them to Ollama for AI analysis.

Usage:
    python generate_report.py                    # Generate report with Ollama analysis
    python generate_report.py --no-interpret     # Raw report only (no Ollama)
    python generate_report.py --type health      # Health-focused report
    python generate_report.py --raw              # Show raw data only
    python generate_report.py --check            # Check Ollama status
"""

import os
import sys
import json
import argparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from daemon.monitoring_report import (
    MonitoringReportGenerator,
    OllamaConfig,
    ReportType,
)


def check_ollama_status(generator: MonitoringReportGenerator) -> None:
    """Check and display Ollama status"""
    print("Checking Ollama status...")
    status = generator.check_ollama_status()

    print(f"\nOllama Status:")
    print(f"  Endpoint: {status['endpoint']}")
    print(f"  Available: {'Yes' if status['available'] else 'No'}")
    print(f"  Configured Model: {status['configured_model']}")

    if status['available']:
        print(f"  Model Available: {'Yes' if status['model_available'] else 'No'}")
        if status['available_models']:
            print(f"  Available Models:")
            for model in status['available_models']:
                marker = " <--" if model == status['configured_model'] else ""
                print(f"    - {model}{marker}")
    else:
        print("\n  Ollama is not running!")
        print("  To start Ollama:")
        print("    1. Install from https://ollama.ai")
        print("    2. Run: ollama serve")
        print(f"    3. Pull model: ollama pull {status['configured_model']}")


def generate_report(
    generator: MonitoringReportGenerator,
    report_type: ReportType,
    interpret: bool,
    show_raw: bool,
) -> None:
    """Generate and display a report"""

    print(f"Generating {report_type.value} report...")

    if interpret:
        status = generator.check_ollama_status()
        if not status['available']:
            print("\nWarning: Ollama is not available. Generating raw report only.")
            print("To enable AI analysis, start Ollama with: ollama serve\n")
            interpret = False

    report = generator.generate_report(
        report_type=report_type,
        interpret=interpret,
    )

    print("\n" + "=" * 70)
    print("BOUNDARY DAEMON MONITORING REPORT")
    print("=" * 70)

    if show_raw:
        print("\nRaw Data:")
        print(json.dumps(report.raw_data, indent=2, default=str))
    else:
        # Show formatted version
        formatted = generator._format_for_llm(report.raw_data)
        print(formatted)

    if report.interpretation:
        print("\n" + "=" * 70)
        print("AI ANALYSIS (powered by Ollama)")
        print("=" * 70)
        print(f"\nModel: {report.ollama_model}")
        print(f"Analysis Time: {report.interpretation_time_ms:.0f}ms")
        print("\n" + "-" * 70)
        print(report.interpretation)
        print("-" * 70)

    print(f"\nReport generated in {report.generation_time_ms:.0f}ms")
    if report.interpretation_time_ms > 0:
        print(f"AI analysis took {report.interpretation_time_ms:.0f}ms")


def main():
    parser = argparse.ArgumentParser(
        description="Generate Boundary Daemon monitoring reports with optional AI analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python generate_report.py                    Generate full report with AI analysis
  python generate_report.py --no-interpret     Generate report without AI
  python generate_report.py --type health      Health-focused report
  python generate_report.py --raw              Show raw JSON data
  python generate_report.py --check            Check Ollama status
  python generate_report.py --model llama3.1   Use different model
        """
    )

    parser.add_argument(
        "--type", "-t",
        choices=["full", "summary", "alerts", "health"],
        default="full",
        help="Type of report to generate (default: full)"
    )

    parser.add_argument(
        "--no-interpret", "-n",
        action="store_true",
        help="Skip Ollama interpretation"
    )

    parser.add_argument(
        "--raw", "-r",
        action="store_true",
        help="Show raw JSON data instead of formatted output"
    )

    parser.add_argument(
        "--check", "-c",
        action="store_true",
        help="Check Ollama status and exit"
    )

    parser.add_argument(
        "--endpoint", "-e",
        default=os.environ.get("OLLAMA_ENDPOINT", "http://localhost:11434"),
        help="Ollama endpoint URL (default: http://localhost:11434)"
    )

    parser.add_argument(
        "--model", "-m",
        default=os.environ.get("OLLAMA_MODEL", "llama3.2"),
        help="Ollama model to use (default: llama3.2)"
    )

    args = parser.parse_args()

    # Create generator
    config = OllamaConfig(
        endpoint=args.endpoint,
        model=args.model,
    )
    generator = MonitoringReportGenerator(ollama_config=config)

    # Note: Without a running daemon, we won't have live data
    # But we can still test Ollama connectivity

    if args.check:
        check_ollama_status(generator)
        return

    report_type = ReportType(args.type)

    try:
        generate_report(
            generator=generator,
            report_type=report_type,
            interpret=not args.no_interpret,
            show_raw=args.raw,
        )
    except KeyboardInterrupt:
        print("\nReport generation cancelled.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError generating report: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
