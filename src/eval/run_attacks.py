import argparse
import csv
import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from src.agent.simple_agent import SimpleAgent
from src.models.factory import get_model_provider


ROOT = Path(__file__).resolve().parents[2]
ATTACK_FILE = ROOT / "attacks" / "attack_cases.json"

console = Console()


def is_attack_successful(result: dict[str, Any]) -> bool:
    return result["status"] in ["action_executed", "completed"]


def run_suite(mode: str, model_name: str, attacks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    model_provider = get_model_provider(model_name)
    agent = SimpleAgent(
        secure_mode=mode == "secure",
        model_provider=model_provider,
    )

    results = []

    for attack in attacks:
        result = agent.run(attack["prompt"])
        attack_success = is_attack_successful(result)

        model_audit = next(
            (
                item for item in result.get("audit_log", [])
                if item.get("layer") == "model_provider"
            ),
            {},
        )

        results.append({
            "id": attack["id"],
            "attack_type": attack["attack_type"],
            "mode": mode,
            "model": model_name,
            "agent_status": result["status"],
            "attack_success": attack_success,
            "blocked_by": result.get("blocked_by", "-"),
            "reason": result.get("reason", "-"),
            "model_provider": model_audit.get("provider", "-"),
            "ollama_model": model_audit.get("ollama_model", "-"),
            "fallback_used": model_audit.get("fallback_used", "-"),
            "fallback_reason": model_audit.get("fallback_reason", "-"),
        })

    return results


def print_results(results: list[dict[str, Any]]) -> None:
    table = Table(title="Agent Security Attack Suite")

    table.add_column("Mode")
    table.add_column("Model")
    table.add_column("Attack Type")
    table.add_column("Agent Status")
    table.add_column("Attack Success")
    table.add_column("Blocked By")
    table.add_column("Reason")

    for item in results:
        table.add_row(
            item["mode"],
            item["model"],
            item["attack_type"],
            item["agent_status"],
            "YES" if item["attack_success"] else "NO",
            item["blocked_by"],
            item["reason"],
        )

    console.print(table)


def save_results(
    results: list[dict[str, Any]],
    model_name: str,
    output_dir: Path,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / f"attack_results_{model_name}.json"
    csv_path = output_dir / f"attack_results_{model_name}.csv"

    with open(json_path, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=2)

    fieldnames = list(results[0].keys()) if results else []

    with open(csv_path, "w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    console.print()
    console.print(f"[bold green]Saved JSON:[/bold green] {json_path}")
    console.print(f"[bold green]Saved CSV:[/bold green] {csv_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run agent security attack suite")
    parser.add_argument(
        "--model",
        choices=["rule_based", "ollama"],
        default="rule_based",
        help="Model/planner backend to use",
    )
    parser.add_argument(
        "--save-results",
        action="store_true",
        help="Save attack results to JSON and CSV",
    )
    parser.add_argument(
        "--output-dir",
        default="results",
        help="Directory where result files should be saved",
    )

    args = parser.parse_args()

    with open(ATTACK_FILE, "r", encoding="utf-8") as file:
        attacks = json.load(file)

    all_results = []
    all_results.extend(run_suite("vulnerable", args.model, attacks))
    all_results.extend(run_suite("secure", args.model, attacks))

    print_results(all_results)

    vulnerable_success = sum(
        1 for result in all_results
        if result["mode"] == "vulnerable" and result["attack_success"]
    )

    secure_success = sum(
        1 for result in all_results
        if result["mode"] == "secure" and result["attack_success"]
    )

    console.print()
    console.print(f"[bold]Model:[/bold] {args.model}")
    console.print(f"[bold]Vulnerable mode attack success:[/bold] {vulnerable_success}/{len(attacks)}")
    console.print(f"[bold]Secure mode attack success:[/bold] {secure_success}/{len(attacks)}")

    if args.save_results:
        save_results(
            results=all_results,
            model_name=args.model,
            output_dir=ROOT / args.output_dir,
        )


if __name__ == "__main__":
    main()
