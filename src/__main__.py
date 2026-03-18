"""CLI for alertiq."""
import sys, json, argparse
from .core import Alertiq

def main():
    parser = argparse.ArgumentParser(description="AlertIQ — AI SOC Analyst. Automated security alert triage, correlation, and incident response.")
    parser.add_argument("command", nargs="?", default="status", choices=["status", "run", "info"])
    parser.add_argument("--input", "-i", default="")
    args = parser.parse_args()
    instance = Alertiq()
    if args.command == "status":
        print(json.dumps(instance.get_stats(), indent=2))
    elif args.command == "run":
        print(json.dumps(instance.manage(input=args.input or "test"), indent=2, default=str))
    elif args.command == "info":
        print(f"alertiq v0.1.0 — AlertIQ — AI SOC Analyst. Automated security alert triage, correlation, and incident response.")

if __name__ == "__main__":
    main()
