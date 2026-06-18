import argparse
from rich import print_json

from src.agent.simple_agent import SimpleAgent


def main():
    parser = argparse.ArgumentParser(description="Agent Security Playground")
    parser.add_argument("--mode", choices=["vulnerable", "secure"], required=True)
    parser.add_argument("--prompt", required=True)

    args = parser.parse_args()

    agent = SimpleAgent(secure_mode=args.mode == "secure")
    result = agent.run(args.prompt)

    print_json(data=result)


if __name__ == "__main__":
    main()
