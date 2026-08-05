"""Loom Python SDK — thin HTTP client. Never bypasses server-side governance."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

import json
import urllib.error
import urllib.request


@dataclass
class Denial:
    reason: str = ""
    message: str = ""
    step: str = ""
    details: Optional[dict[str, str]] = None


@dataclass
class Response:
    allowed: bool = False
    decision: str = "deny"
    denial: Optional[Denial] = None
    output: Optional[dict[str, Any]] = None
    trace_id: str = ""
    audit_id: str = ""
    idempotent_replay: bool = False
    risk: str = ""


@dataclass
class ResourceRef:
    type: str = ""
    id: str = ""


@dataclass
class Client:
    """Remote Loom HTTP client (POST /v1/execute)."""

    base_url: str
    token: str = ""
    timeout: float = 30.0
    user_agent: str = "loom-python-sdk/0.3"

    def call(
        self,
        operation: str,
        *,
        boundary: str,
        input: Optional[Mapping[str, Any]] = None,
        resource: Optional[ResourceRef] = None,
        fields: Optional[list[str]] = None,
        idempotency_key: str = "",
        approval_token: str = "",
        token: Optional[str] = None,
        metadata: Optional[Mapping[str, str]] = None,
        trace_id: str = "",
    ) -> Response:
        url = self.base_url.rstrip("/") + "/v1/execute"
        body: dict[str, Any] = {
            "operation": operation,
            "boundary": boundary,
            "input": dict(input or {}),
            "metadata": {"adapter": "sdk-python", **dict(metadata or {})},
        }
        if resource is not None:
            body["resource"] = {"type": resource.type, "id": resource.id}
        if fields:
            body["fields"] = fields
        if idempotency_key:
            body["idempotency_key"] = idempotency_key
        if approval_token:
            body["approval_token"] = approval_token

        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", self.user_agent)
        bearer = token if token is not None else self.token
        if bearer:
            req.add_header("Authorization", f"Bearer {bearer}")
        if trace_id:
            req.add_header("X-Trace-Id", trace_id)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8")
        except urllib.error.URLError as e:
            return Response(
                allowed=False,
                decision="deny",
                denial=Denial(reason="internal", message=str(e.reason), step="sdk"),
            )

        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            return Response(
                allowed=False,
                decision="deny",
                denial=Denial(reason="internal", message="invalid json response", step="sdk"),
            )

        denial = None
        if obj.get("Denial"):
            d = obj["Denial"]
            denial = Denial(
                reason=d.get("Reason", ""),
                message=d.get("Message", ""),
                step=d.get("Step", ""),
                details=d.get("Details"),
            )
        return Response(
            allowed=bool(obj.get("Allowed")),
            decision=str(obj.get("Decision", "deny")),
            denial=denial,
            output=obj.get("Output"),
            trace_id=str(obj.get("TraceID", "")),
            audit_id=str(obj.get("AuditID", "")),
            idempotent_replay=bool(obj.get("IdempotentReplay")),
            risk=str(obj.get("Risk", "")),
        )


__all__ = ["Client", "Response", "Denial", "ResourceRef"]
