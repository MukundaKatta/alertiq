"""Basic usage example for alertiq."""
from src.core import Alertiq

def main():
    instance = Alertiq(config={"verbose": True})

    print("=== alertiq Example ===\n")

    # Run primary operation
    result = instance.manage(input="example data", mode="demo")
    print(f"Result: {result}")

    # Run multiple operations
    ops = ["manage", "automate", "schedule]
    for op in ops:
        r = getattr(instance, op)(source="example")
        print(f"  {op}: {"✓" if r.get("ok") else "✗"}")

    # Check stats
    print(f"\nStats: {instance.get_stats()}")

if __name__ == "__main__":
    main()
