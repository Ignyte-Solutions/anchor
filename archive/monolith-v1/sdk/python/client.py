from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

import requests


@dataclass(frozen=True)
class IgnyteAnchorClient:
    base_url: str
    session: requests.Session

    def __post_init__(self) -> None:
        if not self.base_url or not self.base_url.strip():
            raise ValueError("base_url is required")
        if self.session is None:
            raise ValueError("session is required")

    def issue_capability(self, request: Dict[str, Any]) -> Dict[str, Any]:
        response = self.session.post(
            f"{self.base_url.rstrip('/')}/v1/capabilities",
            json=request,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        if response.status_code != 201:
            raise RuntimeError(
                f"Issue capability failed ({response.status_code}): {response.text}"
            )
        return response.json()

    def verify_action(self, request: Dict[str, Any]) -> Dict[str, Any]:
        response = self.session.post(
            f"{self.base_url.rstrip('/')}/v1/actions/verify",
            json=request,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"Verify action failed ({response.status_code}): {response.text}"
            )
        return response.json()


def build_verify_request(
    capability: Dict[str, Any],
    action: Dict[str, Any],
    issuer_public_key: str,
    agent_public_key: str,
    revoked_capability_ids: List[str],
) -> Dict[str, Any]:
    if not issuer_public_key:
        raise ValueError("issuer_public_key is required")
    if not agent_public_key:
        raise ValueError("agent_public_key is required")
    return {
        "capability": capability,
        "action": action,
        "issuer_public_key": issuer_public_key,
        "agent_public_key": agent_public_key,
        "revoked_capability_ids": revoked_capability_ids,
    }
