import argparse
from rich import print_json

from src.agent.simple_agent import SimpleAgent
from src.models.factory import get_model_provider


def main():
    parser = argparse.ArgumentParser(description="Agent Security Playground")
    parser.add_argument("--mode", choices=["vulnerable", "secure"], required=True)
    parser.add_argument(
        "--model",
        choices=["rule_based"],
        default="rule_based",
        help="Model/planner backend to use",
    )
    parser.add_argument("--prompt", required=True)

    args = parser.parse_args()

    model_provider = get_model_provider(args.model)
    agent = SimpleAgent(
        secure_mode=args.mode == "secure",
        model_provider=model_provider,
    )

    result = agent.run(args.prompt)

    print_json(data=result)


if __name__ == "__main__":
    main()
