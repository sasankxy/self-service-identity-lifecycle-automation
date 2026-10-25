"""IdentityOS agent layer.

Agents PROPOSE typed tool calls; the Action Gateway (gateway.py) is the only component that executes them, and the deterministic
policy engine (app.services.policy) is the only component that decides. See docs/contract/integration_contract_v1.md.
"""
