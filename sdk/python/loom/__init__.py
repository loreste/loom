"""Loom Python SDK — thin HTTP client. Never bypasses server-side governance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional

import json
import urllib.error
import urllib.request


@dataclass
class Denial:
    reason: str = ""
    message: str = ""
    step: str = ""
    retryable: bool = False
    hint: str = ""
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


def _parse_denial(d: Optional[Mapping[str, Any]]) -> Optional[Denial]:
    if not d:
        return None
    return Denial(
        reason=str(d.get("Reason", d.get("reason", ""))),
        message=str(d.get("Message", d.get("message", ""))),
        step=str(d.get("Step", d.get("step", ""))),
        retryable=bool(d.get("Retryable", d.get("retryable", False))),
        hint=str(d.get("Hint", d.get("hint", ""))),
        details=d.get("Details") or d.get("details"),
    )


def _parse_response(obj: Mapping[str, Any]) -> Response:
    return Response(
        allowed=bool(obj.get("Allowed", obj.get("allowed", False))),
        decision=str(obj.get("Decision", obj.get("decision", "deny"))),
        denial=_parse_denial(obj.get("Denial") or obj.get("denial")),
        output=obj.get("Output") if "Output" in obj else obj.get("output"),
        trace_id=str(obj.get("TraceID", obj.get("trace_id", ""))),
        audit_id=str(obj.get("AuditID", obj.get("audit_id", ""))),
        idempotent_replay=bool(obj.get("IdempotentReplay", obj.get("idempotent_replay", False))),
        risk=str(obj.get("Risk", obj.get("risk", ""))),
    )


@dataclass
class Client:
    """Remote Loom HTTP client (POST /v1/execute + agent discovery)."""

    base_url: str
    token: str = ""
    timeout: float = 30.0
    user_agent: str = "loom-python-sdk/0.4"

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

        return self._post_json(url, body, token=token, trace_id=trace_id)

    def manifest(self) -> dict[str, Any]:
        """GET /.well-known/loom.json — unauthenticated discovery."""
        return self._get_json("/.well-known/loom.json", auth=False)

    def openapi(self, *, token: Optional[str] = None) -> dict[str, Any]:
        """GET /v1/openapi.json — capability-filtered OpenAPI document."""
        return self._get_json("/v1/openapi.json", auth=True, token=token)

    def catalog_spec(self, *, boundary: str, token: Optional[str] = None) -> Response:
        """Call governed catalog.spec for full tool specs."""
        return self.call("catalog.spec", boundary=boundary, input={}, token=token)

    def mcp(self, rpc: Mapping[str, Any], *, token: Optional[str] = None) -> dict[str, Any]:
        """POST /mcp — one JSON-RPC MCP message."""
        url = self.base_url.rstrip("/") + "/mcp"
        data = json.dumps(dict(rpc)).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Loom-Protocol-Version", "1")
        req.add_header("User-Agent", self.user_agent)
        bearer = token if token is not None else self.token
        if bearer:
            req.add_header("Authorization", f"Bearer {bearer}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8")
        except urllib.error.URLError as e:
            return {"error": {"message": str(e.reason)}}
        if not raw.strip():
            return {}
        return json.loads(raw)

    def _post_json(
        self,
        url: str,
        body: Mapping[str, Any],
        *,
        token: Optional[str] = None,
        trace_id: str = "",
    ) -> Response:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Loom-Protocol-Version", "1")
        req.add_header("User-Agent", self.user_agent)
        req.add_header("X-Loom-Protocol-Version", "1")
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
        return _parse_response(obj)

    def _get_json(
        self, path: str, *, auth: bool, token: Optional[str] = None
    ) -> dict[str, Any]:
        url = self.base_url.rstrip("/") + path
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", self.user_agent)
        if auth:
            bearer = token if token is not None else self.token
            if bearer:
                req.add_header("Authorization", f"Bearer {bearer}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8")
        except urllib.error.URLError as e:
            return {"error": str(e.reason)}
        return json.loads(raw)


__all__ = ["Client", "Response", "Denial", "ResourceRef"]
