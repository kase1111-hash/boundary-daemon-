#!/usr/bin/env python3
"""
Boundary Daemon Query Tool

Query the Boundary Daemon using natural language via Ollama.

Usage:
    python query_daemon.py "What is the memory usage?"
    python query_daemon.py --interactive
    python query_daemon.py --check

Examples:
    python query_daemon.py "Are there any critical issues?"
    python query_daemon.py "What security mode is the daemon running in?"
    python query_daemon.py "Is the system healthy?"
    python query_daemon.py "How much disk space is being used?"
"""

import os
import sys
import argparse
import json

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from daemon.monitoring_report import (
    MonitoringReportGenerator,
    OllamaConfig,
)


def check_status(generator: MonitoringReportGenerator) -> bool:
    """Check and display Ollama and daemon status"""
    print("Checking system status...\n")

    # Check Ollama
    status = generator.check_ollama_status()
    print(f"Ollama Status:")
    print(f"  Endpoint: {status['endpoint']}")
    print(f"  Available: {'Yes' if status['available'] else 'No'}")
    print(f"  Model: {status['configured_model']}")

    if not status['available']:
        print("\n  Ollama is not running!")
        print("  Start Ollama with: ollama serve")
        print(f"  Then pull model: ollama pull {status['configured_model']}")
        return False

    if not status['model_available']:
        print(f"\n  Model '{status['configured_model']}' is not available!")
        print(f"  Available models: {', '.join(status['available_models']) or 'None'}")
        print(f"  Pull the model with: ollama pull {status['configured_model']}")
        return False

    print(f"  Model Available: Yes")

    # Check daemon connection (if available)
    if generator.daemon:
        print(f"\nDaemon Status:")
        print(f"  Connected: Yes")
        print(f"  Running: {getattr(generator.daemon, '_running', 'Unknown')}")
    else:
        print(f"\nDaemon Status:")
        print(f"  Connected: No (running standalone)")

    return True


def query_once(generator: MonitoringReportGenerator, question: str) -> None:
    """Execute a single query and display the result"""
    print(f"\nQuestion: {question}")
    print("-" * 60)

    result = generator.query(question)

    if not result.get('success'):
        print(f"Error: {result.get('error', 'Unknown error')}")
        return

    print(f"\n{result.get('answer', 'No answer received')}")
    print("-" * 60)
    print(f"Model: {result.get('model', 'Unknown')}")
    print(f"Response time: {result.get('response_time_ms', 0):.0f}ms")
    print(f"Daemon mode: {result.get('daemon_mode', 'Unknown')}")


def interactive_mode(generator: MonitoringReportGenerator) -> None:
    """Run in interactive query mode"""
    print("=" * 60)
    print("Boundary Daemon Interactive Query")
    print("=" * 60)
    print("\nAsk questions about the daemon in natural language.")
    print("Type 'quit' or 'exit' to stop.")
    print("Type 'status' to check system status.")
    print("Type 'help' for example questions.")
    print("-" * 60)

    example_questions = [
        "What is the current memory usage?",
        "Are there any critical issues?",
        "What security mode is the daemon in?",
        "Is the system healthy?",
        "How much disk space is being used?",
        "What is the CPU usage?",
        "Are there any memory leaks?",
        "How long has the daemon been running?",
        "What alerts have occurred recently?",
        "Is the queue backing up?",
    ]

    while True:
        try:
            question = input("\nYou: ").strip()

            if not question:
                continue

            if question.lower() in ('quit', 'exit', 'q'):
                print("Goodbye!")
                break

            if question.lower() == 'status':
                check_status(generator)
                continue

            if question.lower() == 'help':
                print("\nExample questions you can ask:")
                for q in example_questions:
                    print(f"  - {q}")
                continue

            # Query the daemon
            print("\nThinking...", end="", flush=True)
            result = generator.query(question)

            # Clear the "Thinking..." message
            print("\r" + " " * 20 + "\r", end="")

            if not result.get('success'):
                print(f"Error: {result.get('error', 'Unknown error')}")
                continue

            print(f"\nDaemon: {result.get('answer', 'No answer received')}")
            print(f"\n  [{result.get('response_time_ms', 0):.0f}ms, mode: {result.get('daemon_mode', '?')}]")

        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except EOFError:
            print("\nGoodbye!")
            break


def main():
    parser = argparse.ArgumentParser(
        description="Query the Boundary Daemon using natural language",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python query_daemon.py "What is the memory usage?"
  python query_daemon.py "Are there any issues?"
  python query_daemon.py --interactive
  python query_daemon.py --check
        """
    )

    parser.add_argument(
        "question",
        nargs="?",
        help="Question to ask about the daemon"
    )

    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Run in interactive mode"
    )

    parser.add_argument(
        "--check", "-c",
        action="store_true",
        help="Check Ollama and daemon status"
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

    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output response as JSON"
    )

    args = parser.parse_args()

    # Create generator
    config = OllamaConfig(
        endpoint=args.endpoint,
        model=args.model,
    )
    generator = MonitoringReportGenerator(ollama_config=config)

    # Handle different modes
    if args.check:
        success = check_status(generator)
        sys.exit(0 if success else 1)

    if args.interactive:
        if not check_status(generator):
            sys.exit(1)
        interactive_mode(generator)
        return

    if args.question:
        if args.json:
            result = generator.query(args.question)
            print(json.dumps(result, indent=2))
        else:
            query_once(generator, args.question)
        return

    # No arguments - show help
    parser.print_help()


if __name__ == "__main__":
    main()
