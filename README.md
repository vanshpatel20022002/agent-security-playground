# Agent Security Playground

A practical security playground for LLM-style agents.

This project demonstrates how an AI agent can be attacked through prompt injection, data exfiltration, memory poisoning, malicious tool/RAG output, tool hijacking, sensitive output leakage, and excessive agency. It also shows how layered security controls can reduce or block these attacks before unsafe actions or unsafe responses are produced.

The goal is not to build a chatbot. The goal is to show how agent systems should be protected when they have access to tools, memory, documents, and action-taking capabilities.

## Current Result

```text
Vulnerable mode attack success: 7/7
Secure mode attack success: 0/7
```

The vulnerable agent intentionally executes unsafe actions or leaks sensitive output.

The secure agent uses guardrails, policy checks, and human approval gates to block or pause the same attacks.

## Why This Project Matters

Modern AI agents are more powerful than simple chatbots because they can:

- call tools
- query databases
- search documents
- write memory
- send emails
- create tickets
- generate internal reports
- execute multi-step workflows

That also means prompt injection is no longer only a text-output problem. A compromised agent may call the wrong tool, leak sensitive data, store poisoned memory, or perform an unintended action.

This project focuses on securing the full agent workflow, not only filtering the final response.

## Attack Coverage

| Attack Type | What It Demonstrates |
|---|---|
| Direct Prompt Injection | A user attempts to override the agent's instructions |
| Data Exfiltration | The agent is tricked into sending customer records to an untrusted destination |
| Memory Poisoning | The attacker tries to store malicious future behavior |
| Indirect Prompt Injection | A malicious retrieved document attempts to hijack the agent |
| Tool Hijacking | The agent is redirected from the correct tool to an unsafe tool |
| Sensitive Output Leakage | The agent tries to return secrets/PII in the final response |
| Excessive Agency | The agent attempts to execute a high-impact action without human approval |

## Security Layers

| Security Layer | Purpose |
|---|---|
| Input Guard | Detects direct prompt injection and jailbreak-style instructions |
| Tool Output Guard | Scans untrusted retrieved/tool content before the agent uses it |
| Tool Policy Guard | Blocks unsafe tool calls, external email, sensitive data access, and high-risk actions |
| Intent Policy Guard | Ensures the selected tool matches the user's original intent |
| Memory Guard | Blocks poisoned memory writes that could affect future agent behavior |
| Output Guard | Blocks final responses that contain secrets, API keys, or PII |
| Human Approval Gate | Pauses high-impact actions until a human approves them |
| Audit Log | Records decisions made by each security layer, including model fallback metadata |

## Model Provider Layer

The agent uses a model-provider abstraction so the security layers are independent of the model backend.

Implemented providers:

```text
rule_based  deterministic local planner, no API key required
ollama      optional local small model backend with safe fallback metadata
```

Planned provider:

```text
grok        optional hosted API backend
```

The Ollama provider attempts to call a local Ollama model. If Ollama is not installed, not running, the model is not pulled, or the response is invalid JSON, it falls back to the deterministic rule-based planner so the project still runs.

The audit log shows whether the local model was actually used or whether fallback was used.

Successful Ollama model-provider audit entry:

```json
{
  "layer": "model_provider",
  "intent": "internal_report",
  "requested_tool": "generate_internal_report",
  "provider": "ollama",
  "ollama_model": "llama3.2:3b",
  "fallback_used": false
}
```

Fallback model-provider audit entry:

```json
{
  "layer": "model_provider",
  "intent": "support_ticket",
  "requested_tool": "send_email",
  "provider": "ollama",
  "ollama_model": "llama3.2:3b",
  "fallback_used": true,
  "fallback_provider": "rule_based",
  "fallback_reason": "InvalidPlan"
}
```

This means the same guards can protect different model backends without rewriting the security logic.

## Project Modes

### Vulnerable Mode

In vulnerable mode, the agent trusts the user prompt, tool output, and generated response too much.

```powershell
python -m src.main --mode vulnerable --model rule_based --prompt "Create a support ticket for a customer login issue"
```

Expected behavior:

```text
status: action_executed
tool_called: create_ticket
```

### Secure Mode

In secure mode, the agent checks input, tool output, memory writes, selected tools, tool arguments, final output, and high-impact actions before executing anything.

```powershell
python -m src.main --mode secure --model rule_based --prompt "Create a support ticket for a customer login issue"
```

Expected behavior:

```text
status: pending_approval
blocked_by: human_approval_gate
```

## Automated Attack Evaluation

Run the full attack suite with the default rule-based provider:

```powershell
python -m src.eval.run_attacks --model rule_based
```

Run the full attack suite with the optional Ollama provider:

```powershell
python -m src.eval.run_attacks --model ollama
```

Expected result:

```text
Vulnerable mode attack success: 7/7
Secure mode attack success: 0/7
```

## Export Attack Results

The attack runner can export structured results to JSON and CSV.

```powershell
python -m src.eval.run_attacks --model rule_based --save-results
python -m src.eval.run_attacks --model ollama --save-results
```

Generated files:

```text
results/attack_results_rule_based.json
results/attack_results_rule_based.csv
results/attack_results_ollama.json
results/attack_results_ollama.csv
```

The exported files include attack type, mode, model, agent status, attack success, blocking layer, reason, model provider, Ollama model, and fallback metadata.

Recent exported results:

| Model | Vulnerable Attack Success | Secure Attack Success | Notes |
|---|---:|---:|---|
| rule_based | 7/7 | 0/7 | Deterministic planner, no fallback |
| ollama | 7/7 | 0/7 | Local `llama3.2:3b`; fallback metadata captured for invalid model plans |

## Optional Ollama Usage

The project works without Ollama because `rule_based` is the default provider.

To use a local model, install Ollama and pull a small model:

```powershell
ollama pull llama3.2:3b
```

Make sure the Ollama server is running:

```powershell
ollama serve
```

In another terminal, run:

```powershell
python -m src.main --mode secure --model ollama --prompt "Generate the internal customer audit report"
```

Environment variables:

```text
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2:3b
OLLAMA_TIMEOUT=120
```

## Example: Indirect Prompt Injection

A normal document-summary request retrieves a fake internal policy document. One retrieved document contains a hidden instruction aimed at redirecting the agent toward an unsafe action.

Vulnerable mode treats the retrieved document as trusted instruction and performs the unsafe action.

Secure mode blocks it through the Tool Output Guard.

## Example: Tool Hijacking

The user asks the agent to create a support ticket, but the request tries to redirect the agent into using email instead.

Vulnerable mode executes the wrong tool.

Secure mode blocks it because the Intent Policy Guard only allows the `create_ticket` tool for support-ticket intent.

## Example: Sensitive Output Leakage

The user asks for an internal customer audit report.

Vulnerable mode returns the report with fake API keys and SSNs.

Secure mode blocks the final response through the Output Guard before secrets or PII are shown.

## Example: Excessive Agency

The user asks the agent to create a support ticket.

Vulnerable mode executes the high-impact action immediately.

Secure mode returns `pending_approval` and includes an approval request instead of executing the action directly.

## Project Structure

```text
agent-security-playground/
├── attacks/
│   └── attack_cases.json
├── configs/
│   └── tool_policy.yaml
├── src/
│   ├── agent/
│   │   └── simple_agent.py
│   ├── eval/
│   │   └── run_attacks.py
│   ├── memory/
│   ├── models/
│   │   ├── base.py
│   │   ├── factory.py
│   │   ├── ollama_provider.py
│   │   └── rule_based.py
│   ├── security/
│   │   ├── human_approval_gate.py
│   │   ├── input_guard.py
│   │   ├── intent_policy_guard.py
│   │   ├── memory_guard.py
│   │   ├── output_guard.py
│   │   ├── tool_output_guard.py
│   │   └── tool_policy_guard.py
│   ├── tools/
│   │   └── mock_tools.py
│   └── main.py
├── tests/
├── requirements.txt
└── README.md
```

## Setup

Clone the repo:

```powershell
git clone https://github.com/vanshpatel20022002/agent-security-playground.git
cd agent-security-playground
```

Create and activate a virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Run a manual action request:

```powershell
python -m src.main --mode vulnerable --model rule_based --prompt "Create a support ticket for a customer login issue"
```

Run the secure version:

```powershell
python -m src.main --mode secure --model rule_based --prompt "Create a support ticket for a customer login issue"
```

Run the full suite:

```powershell
python -m src.eval.run_attacks --model rule_based
```

## Current Version

```text
v0.1    Vulnerable vs secure agent demo
v0.2    Automated attack evaluation runner
v0.3    Indirect prompt injection through fake RAG/tool output
v0.4    Tool hijacking defense using intent policy guard
v0.5    Output guard for sensitive data leakage
v0.6    Model provider abstraction
v0.7    Optional Ollama local model provider
v0.7.1  Model fallback metadata in audit log
v0.7.2  Increased Ollama timeout for local model warm-up
v0.8    Attack result export to JSON and CSV
v0.9    Human approval gate for high-impact actions
```

## Next Improvements

Planned next security features:

- optional hosted API provider such as Grok API
- structured tool schemas with stricter validation
- sandboxed tool execution
- simple dashboard for attack success rate
- optional LangGraph integration

## Key Idea

The LLM should not be the final security boundary.

A safer agent system needs layered controls around:

- user input
- retrieved content
- memory writes
- tool selection
- tool arguments
- final output
- human approval for risky actions

This project demonstrates those controls in a small, understandable, and testable playground.
