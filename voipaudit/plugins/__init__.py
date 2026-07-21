"""Plugin registry for voipaudit."""

from __future__ import annotations


def available_plugins() -> dict[str, str]:
    """Returns {plugin_name: category} for every registered plugin —
    used by list-plugins and by the CLI's --modules validation."""
    return {
        "pbx_fingerprint": "recon",
        "register_exposed": "active",
        "transport_security": "recon",
        "toll_fraud_exposure": "invite",
    }
