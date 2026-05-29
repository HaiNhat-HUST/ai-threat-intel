"""
ClaudeProvider stub - implement khi đội chốt dùng Anthropic Claude.

Kế hoạch:
    pip install anthropic
    export ANTHROPIC_API_KEY=...
    export LLM_PROVIDER=claude
    export CLAUDE_MODEL=claude-sonnet-4-6   # default

Implementation mẫu (chưa active):
    import anthropic
    client = anthropic.Anthropic()
    msg = client.messages.create(model=..., max_tokens=1024,
                                 system=SYSTEM, messages=[...])
    response_text = msg.content[0].text
    parsed = json.loads(response_text)   # prompt yêu cầu JSON output
"""
from __future__ import annotations


class ClaudeProvider:
    name = "claude"

    def __init__(self, model: str = "claude-sonnet-4-6"):
        self.model = model
        raise NotImplementedError(
            "ClaudeProvider stub. To activate: pip install anthropic, set "
            "ANTHROPIC_API_KEY, implement classify_attack_pattern / "
            "infer_relationships / infer_severity using the Anthropic SDK."
        )

    def classify_attack_pattern(self, description: str, hints=None):
        raise NotImplementedError

    def infer_relationships(self, entities, context: str = ""):
        raise NotImplementedError

    def infer_severity(self, text: str):
        raise NotImplementedError
