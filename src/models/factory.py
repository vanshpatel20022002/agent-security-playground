from src.models.base import ModelProvider
from src.models.rule_based import RuleBasedModelProvider


def get_model_provider(model_name: str) -> ModelProvider:
    if model_name == "rule_based":
        return RuleBasedModelProvider()

    raise ValueError(
        f"Unsupported model provider: {model_name}. "
        "Currently supported: rule_based"
    )
