"""Generate the kernel_interop_v1 differential vectors.

Proofs are minted (or, for issuer-side edge cases, signed) with the Python
reference implementation (actenon-kernel), then adversarially mutated. The
expected decision for every case is the reference verifier's own decision:
``actenon.verifier.VerifierSDK`` with LOCAL_DEBUG disclosure (granular
refusal codes, exactly as the Kernel's verifier_sdk_v1 conformance harness
runs it), fed through the Kernel's strict JSON ingress
(``actenon.core.json.loads_no_duplicate_keys``).

Where an SDK is intentionally stricter than the reference (it refuses
something the reference accepts, or refuses with a different code), the case
carries an ``sdk_overrides`` entry with the reason. An SDK must never accept
a case whose reference outcome is ``refused``.

Usage (from a virtualenv with the reference installed):

    pip install "actenon-protocol>=1.1.0,<2" actenon-kernel==1.2.1
    python fixtures/kernel_interop_v1/generate.py

The output is deterministic (fixed keys, nonces, ids and clocks).
"""

from __future__ import annotations

import base64
import copy
import json
import os
import sys
import unicodedata
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

warnings.simplefilter("ignore")
os.environ.pop("ACTENON_ENV", None)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature

from actenon.core import ProofVerificationError
from actenon.core.errors import ContractValidationError
from actenon.core.json import loads_no_duplicate_keys, DuplicateJSONKeyError
from actenon.models import AudienceRef, PartyRef, PolicyDecision, PCCB
from actenon.models.contracts import SignatureSpec, parse_timestamp
from actenon.proof import PCCBMinter, VerifierDisclosureMode, build_local_proof_signer
from actenon.proof.canonical import canonicalize_bytes, _canonicalize_json
from actenon.proof.signers.base import b64url_encode
from actenon.verifier import VerifierSDK
from actenon.api.intake import ActionIntentIntakeService

OUT = Path(__file__).resolve().parent / "cases.json"
ED_SEED = bytes([7]) * 32
ED_KID = "ed25519-issuer-2026"


@dataclass(frozen=True)
class Ed25519Signer:
    algorithm: str = "EdDSA"
    key_id: str = ED_KID

    def _priv(self):
        return Ed25519PrivateKey.from_private_bytes(ED_SEED)

    def sign(self, payload: bytes) -> SignatureSpec:
        sig = self._priv().sign(payload)
        return SignatureSpec(algorithm=self.algorithm, key_id=self.key_id, encoding="base64url", value=b64url_encode(sig))

    def verify(self, payload: bytes, signature: SignatureSpec) -> bool:
        # Mirrors actenon.proof.signers.well_known._verify_signature_with_resolved_key
        import re
        if signature.algorithm != self.algorithm or signature.key_id != self.key_id or signature.encoding != "base64url":
            return False
        raw = signature.value
        if not isinstance(raw, str) or not raw or "=" in raw or re.fullmatch(r"[A-Za-z0-9_-]+", raw) is None:
            return False
        try:
            sig = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except Exception:
            return False
        if len(sig) != 64:
            return False
        try:
            self._priv().public_key().verify(sig, payload)
            return True
        except InvalidSignature:
            return False


HS = build_local_proof_signer()
ED = Ed25519Signer()
SIGNERS = {"hs256": HS, "ed25519": ED}

BASE_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
AUDIENCE = {"type": "service", "id": "portable-hello-world-endpoint"}


def fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def base_intent(params=None, **overrides):
    intent = {
        "contract": {"name": "action_intent", "version": "v1"},
        "intent_id": "intent_diff_001",
        "issued_at": fmt(BASE_NOW),
        "expires_at": fmt(BASE_NOW + timedelta(minutes=5)),
        "tenant": {"tenant_id": "tenant_acme"},
        "requester": {"type": "service", "id": "agent_billing", "display_name": "Billing Agent"},
        "action": {
            "name": "payments.refund",
            "capability": "payments.refund",
            "parameters": params if params is not None else {"amount": 25, "currency": "USD", "invoice_id": "inv_123"},
        },
        "target": {"resource_type": "invoice", "resource_id": "inv_123"},
    }
    intent.update(overrides)
    return intent


def make_context(now=BASE_NOW, audience=None, caps=("payments.refund",)):
    return {
        "request_id": "req_diff_001",
        "audience": audience or dict(AUDIENCE),
        "now": fmt(now) if isinstance(now, datetime) else now,
        "scope_capabilities": list(caps),
        "parameter_constraints": {},
        "resource_selectors": [],
    }


def py_context(sdk: VerifierSDK, ctx):
    return sdk.build_context(
        request_id=ctx["request_id"],
        audience=AudienceRef.from_dict(ctx["audience"], "context.audience"),
        now=parse_timestamp(ctx["now"], "context.now"),
        scope_capabilities=tuple(ctx["scope_capabilities"]),
        parameter_constraints=dict(ctx["parameter_constraints"]),
        resource_selectors=tuple(ctx["resource_selectors"]),
    )


def mint(intent_dict, alg="hs256", now=BASE_NOW, escrow_id=None, caps=None, pccb_id="pccb_diff_001", nonce="nonce-diff-000000000001"):
    signer = SIGNERS[alg]
    intent = ActionIntentIntakeService().parse(intent_dict)
    sdk = VerifierSDK(signer)
    ctx = make_context(now=now)
    context = sdk.build_context(
        request_id="req_mint",
        audience=AudienceRef.from_dict(AUDIENCE),
        now=now,
        scope_capabilities=tuple(caps or (intent.action.capability,)),
    )
    pccb = PCCBMinter(signer=signer, issuer=PartyRef(type="service", id="issuer_kernel"),
                      pccb_id_factory=lambda: pccb_id, nonce_factory=lambda: nonce).mint(
        intent,
        decision=PolicyDecision(outcome="allow", summary="diff", rule_evaluations=(), reason_codes=("DIFF",)),
        context=context,
        escrow_id=escrow_id,
    )
    return pccb.to_dict()


def resign(pccb_dict, alg="hs256", raw_canonical=False):
    """Re-sign a PCCB dict as an (arbitrary) issuer would.

    The payload is exactly what the Python reference verifier reconstructs,
    so a Python-accepted proof results unless the mutation is semantic.
    raw_canonical bypasses depth/size limits (simulating a non-Python issuer).
    """
    signer = SIGNERS[alg]
    p = copy.deepcopy(pccb_dict)
    p["signature"] = {"algorithm": signer.algorithm, "key_id": signer.key_id, "encoding": "base64url", "value": "pending"}
    unsigned = PCCB.from_dict(p).unsigned_payload()
    payload = _canonicalize_json(unsigned).encode("utf-8") if raw_canonical else canonicalize_bytes(unsigned)
    p["signature"] = signer.sign(payload).to_dict()
    return p


def action_hash_for(intent_dict, raw_canonical=False):
    from actenon.proof.service import build_action_hash_input
    from actenon.models import ActionIntent
    intent = ActionIntent.from_dict(intent_dict)
    inp = build_action_hash_input(intent)
    if raw_canonical:
        return sha256(_canonicalize_json(inp).encode("utf-8")).hexdigest()
    return sha256(canonicalize_bytes(inp)).hexdigest()


def issue_for(intent_dict, alg="hs256", mutate_pccb=None, raw_canonical=False, **kw):
    """Issue a proof for an intent without the kernel intake's semantic checks
    (simulates a non-Python issuer / hand-built proof), then sign."""
    base = mint(base_intent(), alg=alg, **kw)
    p = copy.deepcopy(base)
    p["intent_id"] = intent_dict["intent_id"]
    p["subject"] = copy.deepcopy(intent_dict["requester"])
    p["tenant"] = copy.deepcopy(intent_dict["tenant"])
    p["action"] = copy.deepcopy(intent_dict["action"])
    p["target"] = copy.deepcopy(intent_dict["target"])
    p["scope"]["capabilities"] = [intent_dict["action"]["capability"]]
    p["expires_at"] = intent_dict["expires_at"]
    p["action_hash"]["value"] = action_hash_for(intent_dict, raw_canonical=raw_canonical)
    if mutate_pccb:
        mutate_pccb(p)
    return resign(p, alg=alg, raw_canonical=raw_canonical)


# ---------------------------------------------------------------- oracle


def classify_exc(exc, stage):
    if isinstance(exc, ProofVerificationError):
        return exc.refusal_code
    if isinstance(exc, DuplicateJSONKeyError):
        return "INVALID_JSON"
    if isinstance(exc, ContractValidationError):
        return "INVALID_INTENT"
    if stage == "intent":
        return "INVALID_INTENT"
    if stage == "pccb":
        return "INVALID_PCCB"
    if stage == "json":
        return "INVALID_JSON"
    return "ERROR:" + type(exc).__name__


def python_decide(intent_raw: str, pccb_raw: str, ctx: dict, skew_ms: int, alg: str, strict: bool):
    signer = SIGNERS[alg]
    loads = loads_no_duplicate_keys if strict else json.loads
    sdk = VerifierSDK(signer, clock_skew_tolerance=timedelta(milliseconds=skew_ms),
                      disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG)
    try:
        intent_doc = loads(intent_raw)
    except Exception as exc:  # noqa: BLE001
        return {"outcome": "refused", "code": classify_exc(exc, "json")}
    try:
        pccb_doc = loads(pccb_raw)
    except Exception as exc:  # noqa: BLE001
        return {"outcome": "refused", "code": classify_exc(exc, "json")}
    try:
        intent = sdk.parse_intent(intent_doc)
    except Exception as exc:  # noqa: BLE001
        return {"outcome": "refused", "code": classify_exc(exc, "intent")}
    try:
        pccb = sdk.parse_pccb(pccb_doc)
    except Exception as exc:  # noqa: BLE001
        return {"outcome": "refused", "code": classify_exc(exc, "pccb")}
    try:
        context = py_context(sdk, ctx)
    except Exception as exc:  # noqa: BLE001
        return {"outcome": "refused", "code": "INVALID_CONTEXT"}
    try:
        sdk.verify(intent=intent, pccb=pccb, context=context)
    except Exception as exc:  # noqa: BLE001
        return {"outcome": "refused", "code": classify_exc(exc, "verify")}
    return {"outcome": "verified", "code": None}


CASES = []

# Parse-level refusals are reported with different codes by each
# implementation (the reference raises plain ValueError / ContractValidationError
# before its verifier runs). They are compared as one class.
INVALID_INPUT_CODES = {
    "INVALID_INTENT", "INVALID_PCCB", "INVALID_JSON", "INVALID_TIMESTAMP",
    "INVALID_CONTEXT", "PROOF_PAYLOAD_INVALID", "UNSUPPORTED_PROTOCOL_VERSION",
    "ACTION_HASH_INVALID",
}

# The Ed25519 variant re-runs the cases that exercise the signed payload and
# the signature path; the purely semantic cases are signer-independent.
ED25519_PREFIXES = (
    "valid", "pccb_", "sig_", "alg_", "kid_", "enc_", "minted_", "subsecond_",
    "frac", "issuer_", "reordered_caps", "dup_caps", "neg_zero", "time_nbf_minus_skew_skew",
    "time_exp_plus_skew_skew", "expired_and_bad_sig", "depth_params_128",
)
MAX_CASE_BYTES = 20_000


def expected_of(decision):
    if decision["outcome"] == "verified":
        return {"outcome": "verified"}
    code = decision["code"]
    return {"outcome": "refused", "reason_code": "INVALID_INPUT" if code in INVALID_INPUT_CODES else code}


def add(case_id, intent, pccb, ctx=None, skew_ms=0, alg="hs256", note=""):
    if alg == "ed25519" and not case_id.startswith(ED25519_PREFIXES):
        return
    intent_raw = intent if isinstance(intent, str) else json.dumps(intent, ensure_ascii=False, separators=(",", ":"))
    pccb_raw = pccb if isinstance(pccb, str) else json.dumps(pccb, ensure_ascii=False, separators=(",", ":"))
    if len(intent_raw) + len(pccb_raw) > MAX_CASE_BYTES:
        return
    ctx = ctx or make_context()
    case = {
        "id": f"{alg}/{case_id}",
        "signer": alg,
        "clock_skew_tolerance_ms": skew_ms,
        "context": ctx,
        "intent": intent_raw,
        "pccb": pccb_raw,
        "expected": expected_of(python_decide(intent_raw, pccb_raw, ctx, skew_ms, alg, strict=True)),
    }
    overrides = {
        sdk: override
        for sdk, override in SDK_OVERRIDES.get(case_id, {}).items()
        if override["outcome"] != case["expected"]["outcome"]
        or override.get("reason_code") != case["expected"].get("reason_code")
    }
    if overrides:
        case["sdk_overrides"] = overrides
    CASES.append(case)


def setp(doc, path, value):
    cur = doc
    for seg in path[:-1]:
        cur = cur[seg]
    if value is DELETE:
        cur.pop(path[-1], None)
    else:
        cur[path[-1]] = value


DELETE = object()



def _stricter(reason, code="INVALID_INPUT", sdks=("go", "rust")):
    return {sdk: {"outcome": "refused", "reason_code": code, "reason": reason} for sdk in sdks}


_EMPTY_OPTIONAL = (
    "Present-but-empty optional strings are refused (the schemas require minLength >= 1). "
    "The reference signs and binds them, but Go cannot distinguish them from absent members, "
    "so both SDKs refuse them rather than bind the wrong document."
)
_NOT_A_STRING = "display_name must be a string (schema); the reference accepts any JSON value."
_BLANK_ID = "Whitespace-only identifiers are refused at parse time (schema identifier pattern)."
_RFC3339 = "Timestamps must be RFC 3339; the reference also accepts other ISO 8601 forms via datetime.fromisoformat."
_BASE64URL = (
    "Signature values must be canonical, unpadded base64url; the reference's decoder also accepts "
    "'=' padding, the standard alphabet and non-zero trailing bits (signature malleability)."
)
_NOT_JSON = "Not valid JSON/Unicode (RFC 8259); refused at parse time instead of failing the action binding."
_GO_CASE_FOLD = (
    "encoding/json binds object members to struct fields case-insensitively, so Go refuses members "
    "that match a field name only case-insensitively instead of acting on a value the reference ignores."
)

_RUST_NUMBERS = (
    "serde_json (without arbitrary_precision) parses integers outside i64::MIN..=u64::MAX, and -0, "
    "as floating point, which the canonicaliser refuses; the reference accepts them as integers."
)

SDK_OVERRIDES: dict = {
    **{case: _stricter(_EMPTY_OPTIONAL) for case in (
        "intent_target_uri_empty", "intent_requester_dn_empty_vs_present", "pccb_intent_id_empty",
        "pccb_display_name_empty", "pccb_issuer_dn_empty", "pccb_escrow_empty",
        "intent_dn_empty_proof_absent", "intent_target_uri_empty_proof_absent", "issuer_signed_dn_empty",
        "issuer_signed_uri_empty", "issuer_signed_audience_uri_empty", "issuer_signed_intent_id_empty",
        "issuer_signed_escrow_empty",
    )},
    "intent_requester_dn_int": _stricter(_NOT_A_STRING),
    "issuer_signed_dn_int": _stricter(_NOT_A_STRING),
    "intent_tenant_space": _stricter(_BLANK_ID),
    "pccb_nbf_lower_t": _stricter(_RFC3339, sdks=("go",)),
    "pccb_nbf_space": _stricter(_RFC3339, sdks=("go",)),
    "pccb_nbf_no_seconds": _stricter(_RFC3339),
    "sig_padded": _stricter(_BASE64URL, "SIGNATURE_INVALID"),
    "sig_std_alphabet": _stricter(_BASE64URL, "SIGNATURE_INVALID"),
    "sig_nontrailing_bits": _stricter(_BASE64URL, "SIGNATURE_INVALID"),
    "nan_param": _stricter(_NOT_JSON),
    "lone_surrogate_param": _stricter(_NOT_JSON),
    "case_Audience_extra": _stricter(_GO_CASE_FOLD, sdks=("go",)),
    "case_Target_intent_extra": _stricter(_GO_CASE_FOLD, sdks=("go",)),
    "case_target_resource_ID_extra": _stricter(_GO_CASE_FOLD, sdks=("go",)),
    **{case: _stricter(_RUST_NUMBERS, sdks=("rust",)) for case in (
        "minted_bigger_ints", "neg_zero_both",
    )},
    "neg_zero_intent": _stricter(_RUST_NUMBERS, "ACTION_MISMATCH", sdks=("rust",)),
}


def mutated(doc, path, value):
    d = copy.deepcopy(doc)
    setp(d, path, value)
    return d


def flip_char(s, idx=5):
    c = s[idx]
    r = "A" if c != "A" else "B"
    return s[:idx] + r + s[idx + 1:]


def gen_for_alg(alg):
    I = base_intent()
    P = mint(I, alg=alg)
    add("valid", I, P, alg=alg)
    add("valid_pretty_reordered", json.dumps(I, indent=3, sort_keys=True), json.dumps(dict(reversed(list(P.items()))), indent=1), alg=alg)

    # --- bound fields on the intent side
    for name, path, val in [
        ("intent_action_name", ["action", "name"], "payments.charge"),
        ("intent_capability", ["action", "capability"], "payments.charge"),
        ("intent_amount", ["action", "parameters", "amount"], 2500),
        ("intent_param_added", ["action", "parameters", "memo"], "x"),
        ("intent_target_id", ["target", "resource_id"], "inv_999"),
        ("intent_target_type", ["target", "resource_type"], "account"),
        ("intent_target_uri_added", ["target", "uri"], "https://x"),
        ("intent_tenant", ["tenant", "tenant_id"], "tenant_evil"),
        ("intent_tenant_attr", ["tenant", "attributes"], {"region": "eu"}),
        ("intent_requester_id", ["requester", "id"], "agent_other"),
        ("intent_requester_type", ["requester", "type"], "human"),
        ("intent_requester_dn_changed", ["requester", "display_name"], "Other"),
        ("intent_requester_dn_removed", ["requester", "display_name"], DELETE),
        ("intent_id", ["intent_id"], "intent_other"),
        ("intent_issued_at", ["issued_at"], fmt(BASE_NOW - timedelta(seconds=1))),
        ("intent_expires_at", ["expires_at"], fmt(BASE_NOW + timedelta(minutes=6))),
        ("intent_constraints_added", ["action", "constraints"], {"max": 1}),
        ("intent_action_scope_added", ["action", "scope"], {"k": 1}),
        ("intent_context_added", ["context"], {"x": 1}),  # unbound -> accept
        ("intent_metadata_added", ["metadata"], {"x": "y"}),  # unbound -> accept
        ("intent_unknown_top", ["unknown_field"], {"x": 1}),
        ("intent_amount_float", ["action", "parameters", "amount"], 25.0),
        ("intent_amount_str", ["action", "parameters", "amount"], "25"),
        ("intent_amount_bool", ["action", "parameters", "amount"], True),
        ("intent_requester_dn_null", ["requester", "display_name"], None),
        ("intent_tenant_attr_null", ["tenant", "attributes"], None),
        ("intent_constraints_null", ["action", "constraints"], None),
        ("intent_target_selectors_null", ["target", "selectors"], None),
        ("intent_params_null", ["action", "parameters"], None),
        ("intent_params_array", ["action", "parameters"], [1]),
        ("intent_contract_v2", ["contract", "version"], "v2"),
        ("intent_tenant_empty", ["tenant", "tenant_id"], ""),
        ("intent_tenant_space", ["tenant", "tenant_id"], " "),
        ("intent_requester_dn_int", ["requester", "display_name"], 123),
        ("intent_target_uri_empty", ["target", "uri"], ""),
        ("intent_requester_dn_empty_vs_present", ["requester", "display_name"], ""),
    ]:
        add(name, mutated(I, path, val), P, alg=alg)

    # --- bound fields on the pccb side (must break signature)
    for name, path, val in [
        ("pccb_action_name", ["action", "name"], "payments.charge"),
        ("pccb_amount", ["action", "parameters", "amount"], 2500),
        ("pccb_target", ["target", "resource_id"], "inv_999"),
        ("pccb_audience", ["audience", "id"], "other-endpoint"),
        ("pccb_audience_uri", ["audience", "uri"], "https://x"),
        ("pccb_tenant", ["tenant", "tenant_id"], "tenant_evil"),
        ("pccb_subject", ["subject", "id"], "agent_other"),
        ("pccb_issuer", ["issuer", "id"], "issuer_evil"),
        ("pccb_action_hash", ["action_hash", "value"], "0" * 64),
        ("pccb_hash_label_legacy", ["action_hash", "canonicalization"], "RFC8785-JCS"),
        ("pccb_nonce", ["nonce"], "nonce-other"),
        ("pccb_id", ["pccb_id"], "pccb_other"),
        ("pccb_intent_id", ["intent_id"], "intent_other"),
        ("pccb_intent_id_removed", ["intent_id"], DELETE),
        ("pccb_intent_id_empty", ["intent_id"], ""),
        ("pccb_intent_id_null", ["intent_id"], None),
        ("pccb_scope_caps", ["scope", "capabilities"], ["payments.refund", "payments.charge"]),
        ("pccb_scope_single_use", ["scope", "single_use"], False),
        ("pccb_scope_mode", ["scope", "mode"], "prefix"),
        ("pccb_nbf_earlier", ["not_before"], fmt(BASE_NOW - timedelta(hours=1))),
        ("pccb_exp_later", ["expires_at"], fmt(BASE_NOW + timedelta(hours=1))),
        ("pccb_nbf_offset_equiv", ["not_before"], "2026-01-01T13:00:00+01:00"),
        ("pccb_nbf_plus0000", ["not_before"], "2026-01-01T12:00:00+00:00"),
        ("pccb_nbf_frac_zero", ["not_before"], "2026-01-01T12:00:00.000Z"),
        ("pccb_nbf_frac_half", ["not_before"], "2026-01-01T12:00:00.5Z"),
        ("pccb_nbf_lower_z", ["not_before"], "2026-01-01T12:00:00z"),
        ("pccb_nbf_lower_t", ["not_before"], "2026-01-01t12:00:00Z"),
        ("pccb_nbf_space", ["not_before"], "2026-01-01 12:00:00Z"),
        ("pccb_nbf_no_seconds", ["not_before"], "2026-01-01T12:00Z"),
        ("pccb_nbf_leap", ["not_before"], "2026-01-01T11:59:60Z"),
        ("pccb_nbf_neg0", ["not_before"], "2026-01-01T12:00:00-00:00"),
        ("pccb_display_name_empty", ["subject", "display_name"], ""),
        ("pccb_issuer_dn_empty", ["issuer", "display_name"], ""),
        ("pccb_escrow_empty", ["escrow_reference"], {"escrow_id": ""}),
        ("pccb_escrow_space", ["escrow_reference"], {"escrow_id": " "}),
        ("pccb_escrow_null", ["escrow_reference"], None),
        ("pccb_extensions_empty", ["extensions"], {}),
        ("pccb_extensions_null", ["extensions"], None),
        ("pccb_unknown_top", ["unknown_field"], {"x": 1}),
        ("pccb_sig_extra_field", ["signature", "extra"], "x"),
        ("pccb_tenant_attr_null", ["tenant", "attributes"], None),
        ("pccb_scope_selectors_null", ["scope", "resource_selectors"], None),
        ("pccb_scope_pc_null", ["scope", "parameter_constraints"], None),
        ("pccb_scope_single_use_str", ["scope", "single_use"], "true"),
        ("pccb_caps_str", ["scope", "capabilities"], "payments.refund"),
        ("pccb_caps_dup", ["scope", "capabilities"], ["payments.refund", "payments.refund"]),
        ("pccb_contract_extra", ["contract", "extra"], "x"),
    ]:
        add(name, I, mutated(P, path, val), alg=alg)

    # --- signature-level mutations
    sig = P["signature"]["value"]
    for name, val in [
        ("sig_bitflip", flip_char(sig)),
        ("sig_truncated", sig[:-2]),
        ("sig_padded", sig + "="),
        ("sig_padded2", sig + "=="),
        ("sig_newline", sig[:10] + "\n" + sig[10:]),
        ("sig_crlf", sig[:10] + "\r\n" + sig[10:]),
        ("sig_space", sig[:10] + " " + sig[10:]),
        ("sig_std_alphabet", sig.replace("-", "+").replace("_", "/")),
        ("sig_empty", ""),
        ("sig_nontrailing_bits", sig[:-1] + chr(ord(sig[-1]) ^ 1) if sig[-1] not in "AQgw" else sig[:-1] + {"A": "B", "Q": "R", "g": "h", "w": "x"}[sig[-1]]),
    ]:
        add(name, I, mutated(P, ["signature", "value"], val), alg=alg)
    for name, path, val in [
        ("alg_none", ["signature", "algorithm"], "none"),
        ("alg_lower", ["signature", "algorithm"], P["signature"]["algorithm"].lower()),
        ("alg_other", ["signature", "algorithm"], "HS256" if alg == "ed25519" else "EdDSA"),
        ("alg_hs512", ["signature", "algorithm"], "HS512"),
        ("alg_missing", ["signature", "algorithm"], DELETE),
        ("alg_null", ["signature", "algorithm"], None),
        ("alg_int", ["signature", "algorithm"], 256),
        ("kid_swap", ["signature", "key_id"], "other-key"),
        ("kid_missing", ["signature", "key_id"], DELETE),
        ("kid_empty", ["signature", "key_id"], ""),
        ("enc_base64", ["signature", "encoding"], "base64"),
        ("enc_upper", ["signature", "encoding"], "BASE64URL"),
        ("sig_missing", ["signature"], DELETE),
    ]:
        add(name, I, mutated(P, path, val), alg=alg)

    # alg confusion: HS256 keyed with the Ed25519 public key bytes
    import hmac as _hmac
    pub = Ed25519PrivateKey.from_private_bytes(ED_SEED).public_key().public_bytes_raw()
    conf = copy.deepcopy(P)
    conf["signature"] = {"algorithm": "HS256", "key_id": ED_KID, "encoding": "base64url", "value": "x"}
    payload = canonicalize_bytes(PCCB.from_dict(conf).unsigned_payload())
    conf["signature"]["value"] = b64url_encode(_hmac.new(pub, payload, sha256).digest())
    add("alg_confusion_hs256_with_ed_pubkey", I, conf, alg=alg)
    conf2 = copy.deepcopy(conf)
    conf2["signature"]["key_id"] = "local-proof-v1"
    add("alg_confusion_hs256_with_ed_pubkey_localkid", I, conf2, alg=alg)
    # none alg with empty sig
    none = mutated(P, ["signature"], {"algorithm": "none", "key_id": P["signature"]["key_id"], "encoding": "base64url", "value": "AA"})
    add("alg_none_sig_AA", I, none, alg=alg)

    # --- time boundaries (nbf = BASE_NOW, exp = BASE_NOW + 5m)
    nbf, exp = BASE_NOW, BASE_NOW + timedelta(minutes=5)
    for skew in (0, 2000):
        s = timedelta(milliseconds=skew)
        for label, now in [
            ("nbf_minus_skew_minus1s", nbf - s - timedelta(seconds=1)),
            ("nbf_minus_skew", nbf - s),
            ("nbf_minus_skew_minus1us", nbf - s - timedelta(microseconds=1)),
            ("nbf", nbf),
            ("exp", exp),
            ("exp_plus_skew", exp + s),
            ("exp_plus_skew_plus1us", exp + s + timedelta(microseconds=1)),
            ("exp_plus_skew_plus1s", exp + s + timedelta(seconds=1)),
        ]:
            add(f"time_{label}_skew{skew}", I, P, ctx=make_context(now=now), skew_ms=skew, alg=alg)
    # expired + bad signature (order of checks)
    add("expired_and_bad_sig", I, mutated(P, ["signature", "value"], flip_char(sig)), ctx=make_context(now=exp + timedelta(hours=1)), alg=alg)
    add("not_yet_valid_and_bad_sig", I, mutated(P, ["signature", "value"], flip_char(sig)), ctx=make_context(now=nbf - timedelta(hours=1)), alg=alg)
    # multi-mismatch ordering
    m = mutated(I, ["target", "resource_id"], "inv_999")
    setp(m, ["tenant", "tenant_id"], "tenant_evil")
    add("multi_target_and_tenant", m, P, alg=alg)
    add("multi_audience_and_expired", I, P, ctx=make_context(now=exp + timedelta(hours=1), audience={"type": "service", "id": "x"}), alg=alg)
    m = mutated(I, ["target", "resource_id"], "inv_999")
    setp(m, ["action", "capability"], "payments.charge")
    add("multi_target_and_capability", m, P, alg=alg)
    # context audience mismatches
    add("ctx_audience_id", I, P, ctx=make_context(audience={"type": "service", "id": "other"}), alg=alg)
    add("ctx_audience_type", I, P, ctx=make_context(audience={"type": "api", "id": AUDIENCE["id"]}), alg=alg)
    add("ctx_audience_uri", I, P, ctx=make_context(audience={**AUDIENCE, "uri": "https://x"}), alg=alg)

    # --- raw JSON text attacks
    Iraw = json.dumps(I)
    Praw = json.dumps(P)
    add("dup_param_key_same", Iraw.replace('"amount": 25', '"amount": 25, "amount": 25'), Praw, alg=alg)
    add("dup_param_key_diff_last_signed", Iraw.replace('"amount": 25', '"amount": 2500, "amount": 25'), Praw, alg=alg)
    add("dup_param_key_diff_first_signed", Iraw.replace('"amount": 25', '"amount": 25, "amount": 2500'), Praw, alg=alg)
    add("dup_top_audience_pccb", Iraw, Praw[:-1] + ', "audience": {"type": "service", "id": "evil"}}', alg=alg)
    add("dup_top_audience_pccb_signed_last", Iraw, '{"audience": {"type": "service", "id": "evil"}, ' + Praw[1:], alg=alg)
    add("case_Audience_extra", Iraw, Praw[:-1] + ', "Audience": {"type": "service", "id": "evil"}}', alg=alg)
    add("case_AUDIENCE_only", Iraw, Praw.replace('"audience":', '"AUDIENCE":'), alg=alg)
    add("case_Target_intent_extra", Iraw[:-1] + ', "Target": {"resource_type": "invoice", "resource_id": "inv_999"}}', Praw, alg=alg)
    add("case_target_resource_ID_extra", Iraw.replace('"resource_id": "inv_123"}', '"resource_id": "inv_123", "Resource_ID": "inv_999"}'), Praw, alg=alg)
    add("case_longs_scope", Iraw, Praw.replace('"scope":', '"\u017fcope":'), alg=alg)
    add("case_kelvin_key_id", Iraw, Praw.replace('"key_id":', '"\u212aey_id":'), alg=alg)
    add("trailing_garbage_intent", Iraw + " x", Praw, alg=alg)
    add("two_objects_pccb", Iraw, Praw + " {}", alg=alg)
    add("bom_intent", "\ufeff" + Iraw, Praw, alg=alg)
    add("top_level_array", "[" + Iraw + "]", Praw, alg=alg)
    add("nan_param", Iraw.replace('"amount": 25', '"amount": NaN'), Praw, alg=alg)
    add("amount_25_0", Iraw.replace('"amount": 25', '"amount": 25.0'), Praw, alg=alg)
    add("amount_2_5e1", Iraw.replace('"amount": 25', '"amount": 2.5e1'), Praw, alg=alg)
    add("amount_25e0", Iraw.replace('"amount": 25', '"amount": 25e0'), Praw, alg=alg)
    add("amount_escaped_key", Iraw.replace('"amount": 25', '"\\u0061mount": 25'), Praw, alg=alg)
    add("currency_escaped_value", Iraw.replace('"USD"', '"\\u0055SD"'), Praw, alg=alg)
    add("lone_surrogate_param", Iraw.replace('"USD"', '"\\ud800"'), Praw, alg=alg)

    # --- values minted by the kernel itself (Python accepts) with tricky content
    tricky_params = {
        "html": {"note": "<b>Tom & Jerry</b> > 1"},
        "u2028": {"note": "line\u2028sep\u2029para"},
        "unicode_nfc": {"name": "caf\u00e9", "jp": "\u65e5\u672c\u8a9e"},
        "emoji": {"name": "\U0001F600 grin", "\U0001F600": 1},
        "control": {"note": "a\u0001b\u001fc\u007fd\ttab\nnl"},
        "keys_order": {"\u00e9": 1, "Z": 2, "a": 3, "\U0001F600": 4, "\uff21": 5},
        "big_ints": {"u64max": 18446744073709551615, "i64min": -9223372036854775808, "i64max": 9223372036854775807},
        "bigger_ints": {"p64": 18446744073709551616, "n64": -9223372036854775809, "huge": 10 ** 30},
        "neg_zero_as_int": {"z": 0, "neg": -1},
        "nested": {"a": {"b": [1, {"c": None, "d": True, "e": False}, []], "f": {}}},
        "escape_chars": {"q": 'she said "hi"', "bs": "C:\\Users\\x", "slash": "a/b"},
        "empty_string_key": {"": "empty key"},
        "long_string": {"blob": "x" * 100_000},
    }
    for name, params in tricky_params.items():
        intent = base_intent(params=params)
        try:
            proof = mint(intent, alg=alg)
        except Exception as exc:  # noqa: BLE001
            print("mint failed", name, exc, file=sys.stderr)
            continue
        add(f"minted_{name}", intent, proof, alg=alg)
    # -0 in intent where proof has 0
    intent0 = base_intent(params={"z": 0, "amount": 25})
    p0 = mint(intent0, alg=alg)
    add("neg_zero_intent", json.dumps(intent0).replace('"z": 0', '"z": -0'), p0, alg=alg)
    add("neg_zero_both", json.dumps(intent0).replace('"z": 0', '"z": -0'), json.dumps(p0).replace('"z": 0', '"z": -0'), alg=alg)
    # NFD vs NFC mismatch
    intent_nfc = base_intent(params={"name": unicodedata.normalize("NFC", "caf\u00e9")})
    p_nfc = mint(intent_nfc, alg=alg)
    add("nfd_intent_vs_nfc_proof", base_intent(params={"name": unicodedata.normalize("NFD", "caf\u00e9")}), p_nfc, alg=alg)

    # --- sub-second timestamps minted by the kernel
    for label, now in [("micro_123456", BASE_NOW + timedelta(microseconds=123456)),
                       ("micro_500000", BASE_NOW + timedelta(microseconds=500000)),
                       ("micro_000001", BASE_NOW + timedelta(microseconds=1))]:
        intent = base_intent(issued_at=fmt(now), expires_at=fmt(now + timedelta(minutes=5)))
        proof = mint(intent, alg=alg, now=now)
        add(f"subsecond_{label}", intent, proof, ctx=make_context(now=now + timedelta(seconds=1)), alg=alg)
        add(f"subsecond_{label}_before_nbf", intent, proof, ctx=make_context(now=now - timedelta(microseconds=1)), alg=alg)
    # 7-digit fractional seconds in the presented PCCB / intent (Python truncates to micro)
    now = BASE_NOW + timedelta(microseconds=123456)
    intent = base_intent(issued_at=fmt(now), expires_at=fmt(now + timedelta(minutes=5)))
    proof = mint(intent, alg=alg, now=now)
    add("frac7_pccb_nbf", intent, mutated(proof, ["not_before"], "2026-01-01T12:00:00.1234567Z"), ctx=make_context(now=now + timedelta(seconds=1)), alg=alg)
    add("frac9_intent_issued", mutated(intent, ["issued_at"], "2026-01-01T12:00:00.123456999Z"), proof, ctx=make_context(now=now + timedelta(seconds=1)), alg=alg)

    # --- escrow + intent_id-less proofs minted by the kernel
    pe = mint(I, alg=alg, escrow_id="escrow_001")
    add("minted_escrow", I, pe, alg=alg)
    add("minted_escrow_single_use_tamper", I, mutated(pe, ["escrow_reference", "single_use"], False), alg=alg)
    add("minted_escrow_removed", I, mutated(pe, ["escrow_reference"], DELETE), alg=alg)
    add("escrow_added_to_plain", I, mutated(P, ["escrow_reference"], {"escrow_id": "escrow_x"}), alg=alg)

    # --- capabilities ordering (issuer-signed unsorted; reordered presentation)
    unsorted = issue_for(I, alg=alg, mutate_pccb=lambda p: p["scope"].__setitem__("capabilities", ["payments.refund", "a.read"]))
    add("issuer_unsorted_caps", I, unsorted, alg=alg)
    sorted_caps = issue_for(I, alg=alg, mutate_pccb=lambda p: p["scope"].__setitem__("capabilities", ["a.read", "payments.refund"]))
    add("issuer_sorted_caps", I, sorted_caps, alg=alg)
    add("reordered_caps_presented", I, mutated(sorted_caps, ["scope", "capabilities"], ["payments.refund", "a.read"]), alg=alg)
    add("dup_caps_presented", I, mutated(sorted_caps, ["scope", "capabilities"], ["a.read", "payments.refund", "payments.refund"]), alg=alg)

    # --- presence ("" vs absent) with issuer-signed proofs
    add("intent_dn_empty_proof_absent",
        mutated(mutated(I, ["requester", "display_name"], DELETE), ["requester", "display_name"], ""),
        issue_for(mutated(I, ["requester", "display_name"], DELETE), alg=alg), alg=alg)
    add("intent_target_uri_empty_proof_absent", mutated(I, ["target", "uri"], ""), issue_for(I, alg=alg), alg=alg)
    add("issuer_signed_dn_empty", mutated(I, ["requester", "display_name"], ""), issue_for(mutated(I, ["requester", "display_name"], ""), alg=alg), alg=alg)
    add("issuer_signed_uri_empty", mutated(I, ["target", "uri"], ""), issue_for(mutated(I, ["target", "uri"], ""), alg=alg), alg=alg)
    add("issuer_signed_audience_uri_empty", I, issue_for(I, alg=alg, mutate_pccb=lambda p: p["audience"].__setitem__("uri", "")), ctx=make_context(audience={**AUDIENCE, "uri": ""}), alg=alg)
    add("issuer_signed_intent_id_empty", I, issue_for(I, alg=alg, mutate_pccb=lambda p: p.__setitem__("intent_id", "")), alg=alg)
    add("issuer_signed_intent_id_absent", I, issue_for(I, alg=alg, mutate_pccb=lambda p: p.pop("intent_id")), alg=alg)
    add("issuer_signed_escrow_empty", I, issue_for(I, alg=alg, mutate_pccb=lambda p: p.__setitem__("escrow_reference", {"escrow_id": ""})), alg=alg)
    add("issuer_signed_dn_int", mutated(I, ["requester", "display_name"], 7), issue_for(mutated(I, ["requester", "display_name"], 7), alg=alg), alg=alg)

    # --- issuer-signed semantic oddities the kernel intake refuses
    bad_window = base_intent(expires_at=fmt(BASE_NOW))
    add("issuer_signed_window_equal", bad_window, issue_for(bad_window, alg=alg, mutate_pccb=lambda p: p.__setitem__("expires_at", fmt(BASE_NOW + timedelta(minutes=5)))), alg=alg)
    inverted = base_intent(expires_at=fmt(BASE_NOW - timedelta(minutes=1)))
    add("issuer_signed_window_inverted", inverted, issue_for(inverted, alg=alg, mutate_pccb=lambda p: p.__setitem__("expires_at", fmt(BASE_NOW + timedelta(minutes=5)))), alg=alg)
    empty_params = base_intent(params={})
    add("issuer_signed_empty_params", empty_params, issue_for(empty_params, alg=alg), alg=alg)
    # hash label: legacy label (re-signed) and unknown label
    add("issuer_signed_legacy_label", I, issue_for(I, alg=alg, mutate_pccb=lambda p: p["action_hash"].__setitem__("canonicalization", "RFC8785-JCS")), alg=alg)
    add("issuer_signed_unknown_label", I, issue_for(I, alg=alg, mutate_pccb=lambda p: p["action_hash"].__setitem__("canonicalization", "JSON-LD")), alg=alg)
    add("issuer_signed_hash_alg_sha512", I, issue_for(I, alg=alg, mutate_pccb=lambda p: p["action_hash"].__setitem__("algorithm", "sha-512")), alg=alg)
    add("issuer_signed_hash_upper", I, issue_for(I, alg=alg, mutate_pccb=lambda p: p["action_hash"].__setitem__("value", p["action_hash"]["value"].upper())), alg=alg)
    add("issuer_signed_scope_mode_prefix", I, issue_for(I, alg=alg, mutate_pccb=lambda p: p["scope"].__setitem__("mode", "prefix")), alg=alg)
    add("issuer_signed_caps_missing_intent_cap", I, issue_for(I, alg=alg, mutate_pccb=lambda p: p["scope"].__setitem__("capabilities", ["x.read"])), alg=alg)
    add("issuer_signed_nbf_after_exp", I, issue_for(I, alg=alg, mutate_pccb=lambda p: p.__setitem__("not_before", fmt(BASE_NOW + timedelta(minutes=10)))), ctx=make_context(now=BASE_NOW + timedelta(minutes=10)), alg=alg)
    add("issuer_signed_extensions", I, issue_for(I, alg=alg, mutate_pccb=lambda p: p.__setitem__("extensions", {"x": [1, {"y": None}]})), alg=alg)
    add("issuer_signed_pccb_frac_nbf", I, issue_for(I, alg=alg, mutate_pccb=lambda p: p.__setitem__("not_before", "2026-01-01T11:59:59.900000Z")), alg=alg)
    add("issuer_signed_pccb_frac_nbf_presented_short", I, mutated(issue_for(I, alg=alg, mutate_pccb=lambda p: p.__setitem__("not_before", "2026-01-01T11:59:59.900000Z")), ["not_before"], "2026-01-01T11:59:59.9Z"), alg=alg)
    # timestamps presented as +00:00 on an issuer-signed frac proof
    # depth: 127 / 128 / 129 / 300 nested parameters
    for depth in (120, 124, 125, 126, 127, 128, 200, 1000):
        v = 1
        for _ in range(depth):
            v = {"n": v}
        intent = base_intent(params={"deep": v})
        try:
            proof = issue_for(intent, alg=alg, raw_canonical=True)
        except RecursionError:
            continue
        add(f"depth_params_{depth}", intent, proof, alg=alg)
    # oversized: canonical output > 1 MiB
    big = base_intent(params={"blob": "x" * (1_048_576 + 10)})
    add("oversized_param_1MiB", big, issue_for(big, alg=alg, raw_canonical=True), alg=alg)
    # canonical size just under: fits in both? (payload includes everything)
    big2 = base_intent(params={"blob": "x" * (1_048_576 - 3000)})
    add("near_limit_param", big2, issue_for(big2, alg=alg, raw_canonical=True), alg=alg)


# ------------------------------------------------------------ trust artifacts
#
# Receipt counter-signatures, approval artifacts and transparency inclusion
# checks, signed with the Ed25519 issuer key above and decided by the
# reference's actenon.verifier.{countersignature,trust_artifacts,transparency}.

ARTIFACTS_OUT = Path(__file__).resolve().parent / "artifacts.json"
KERNEL_VECTORS = Path(__file__).resolve().parent.parent  # vendored conformance vectors


def _ed_sign_statement(statement) -> str:
    return b64url_encode(Ed25519PrivateKey.from_private_bytes(ED_SEED).sign(canonicalize_bytes(statement)))


def _trusted_keys(issuer, uses):
    pub = Ed25519PrivateKey.from_private_bytes(ED_SEED).public_key().public_bytes_raw()
    return {
        "contract": {"name": "key_discovery", "version": "v1"},
        "issuer": issuer,
        "keys": [{
            "key_id": ED_KID,
            "algorithm": "EdDSA",
            "use": uses,
            "status": "active",
            "public_key_jwk": {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(pub), "kid": ED_KID, "alg": "EdDSA"},
        }],
    }


def _decide(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "code", None)
        if code is None:
            raise
        return {"outcome": "refused", "reason_code": code}
    return {"outcome": "verified"}


def _countersignature(digest, *, witness, signed_at="2026-06-06T12:00:00Z", anchor=DELETE, label=None):
    digest = dict(digest)
    if label is not None:
        digest["canonicalization"] = label
    statement = {
        "context": "actenon.receipt-countersignature.v1",
        "receipt_digest": digest,
        "witness": witness,
        "signed_at": signed_at,
    }
    artifact = {
        "contract": {"name": "receipt_countersignature", "version": "v1"},
        "receipt_digest": digest,
        "witness": witness,
        "signed_at": signed_at,
    }
    if anchor is not DELETE:
        artifact["anchor_reference"] = anchor
        if anchor is not None:
            statement["anchor_reference"] = anchor
    artifact["signature"] = {"algorithm": "EdDSA", "key_id": ED_KID, "encoding": "base64url", "value": _ed_sign_statement(statement)}
    return artifact


def _approval(action_hash, *, approver, issued_at="2026-06-06T12:00:00Z"):
    statement = {
        "context": "actenon.approval-artifact.v1",
        "approval_id": "approval_interop_001",
        "approver": approver,
        "approval_type": "finance_approver",
        "decision": "approved",
        "action_hash": action_hash,
        "issued_at": issued_at,
    }
    artifact = {
        "contract": {"name": "approval_artifact", "version": "v1"},
        "approval_id": statement["approval_id"],
        "approver": approver,
        "approval_type": statement["approval_type"],
        "decision": "approved",
        "action_hash": action_hash,
        "issued_at": issued_at,
    }
    artifact["signature"] = {"algorithm": "EdDSA", "key_id": ED_KID, "encoding": "base64url", "value": _ed_sign_statement(statement)}
    return artifact


def generate_artifacts():
    from actenon.models import build_artifact_digest
    from actenon.verifier.countersignature import verify_countersignature
    from actenon.verifier.trust_artifacts import verify_approval_artifact
    from actenon.verifier.transparency import verify_inclusion

    witness = {"type": "service", "id": "witness_interop"}
    approver = {"type": "human", "id": "approver_interop"}
    cs_keys = _trusted_keys(witness, ["receipt_countersignature"])
    ap_keys = _trusted_keys(approver, "approval_artifact")
    receipt = json.loads((KERNEL_VECTORS / "receipt_countersignature_v1" / "receipt.json").read_text(encoding="utf-8"))
    digest = build_artifact_digest(receipt).to_dict()
    legacy_digest = {**digest, "canonicalization": "RFC8785-JCS"}

    countersignatures = []

    def cs(case_id, receipt_or_digest, artifact):
        countersignatures.append({
            "id": case_id,
            "receipt_or_digest": receipt_or_digest,
            "countersignature": artifact,
            "expected": _decide(lambda: verify_countersignature(receipt_or_digest, artifact, cs_keys)),
        })

    good = _countersignature(digest, witness=witness)
    cs("receipt_current_profile", receipt, good)
    cs("digest_current_profile", digest, good)
    cs("digest_legacy_label_vs_current_profile", legacy_digest, good)
    cs("legacy_profile_countersignature", receipt, _countersignature(legacy_digest, witness=witness))
    cs("unknown_profile_label", receipt, _countersignature(digest, witness=witness, label="JSON-LD"))
    cs("anchor_reference_null", receipt, _countersignature(digest, witness=witness, anchor=None))
    cs("anchor_reference_object", receipt, _countersignature(digest, witness=witness, anchor={"log_id": "log-1", "leaf_index": 3}))
    crlf = copy.deepcopy(good)
    crlf["signature"]["value"] = crlf["signature"]["value"][:20] + "\r\n" + crlf["signature"]["value"][20:]
    cs("signature_value_crlf", receipt, crlf)
    padded = copy.deepcopy(good)
    padded["signature"]["value"] += "="
    cs("signature_value_padded", receipt, padded)
    extra_contract = copy.deepcopy(good)
    extra_contract["contract"]["extra"] = "x"
    cs("contract_extra_member", receipt, extra_contract)

    approvals = []
    intent_hash = {"algorithm": "sha-256", "canonicalization": "ACTENON-JCS-STRICT-1", "value": action_hash_for(base_intent())}

    def ap(case_id, artifact, expected_action):
        approvals.append({
            "id": case_id,
            "approval": artifact,
            "expected_action_hash": expected_action,
            "expected": _decide(lambda: verify_approval_artifact(artifact, ap_keys, expected_action=expected_action)),
        })

    good_ap = _approval(intent_hash, approver=approver)
    ap("current_profile", good_ap, intent_hash)
    ap("current_profile_expected_legacy_label", good_ap, {**intent_hash, "canonicalization": "RFC8785-JCS"})
    ap("legacy_profile_expected_current_label", _approval({**intent_hash, "canonicalization": "RFC8785-JCS"}, approver=approver), intent_hash)
    ap("different_action", good_ap, {**intent_hash, "value": "0" * 64})
    ap("unknown_profile_label", _approval({**intent_hash, "canonicalization": "JSON-LD"}, approver=approver), None)
    ap("expected_hash_unknown_label", good_ap, {**intent_hash, "canonicalization": "JSON-LD"})
    crlf_ap = copy.deepcopy(good_ap)
    crlf_ap["signature"]["value"] = crlf_ap["signature"]["value"][:20] + "\n" + crlf_ap["signature"]["value"][20:]
    ap("signature_value_lf", crlf_ap, intent_hash)
    extra_ap = copy.deepcopy(good_ap)
    extra_ap["contract"]["extra"] = "x"
    ap("contract_extra_member", extra_ap, intent_hash)

    inclusions = []
    tl = KERNEL_VECTORS / "transparency_log_v1"
    proof = json.loads((tl / "inclusion_proof.json").read_text(encoding="utf-8"))
    checkpoint = json.loads((tl / "checkpoint_new.json").read_text(encoding="utf-8"))

    def inc(case_id, leaf_digest, proof_doc):
        inclusions.append({
            "id": case_id,
            "digest": leaf_digest,
            "inclusion_proof": proof_doc,
            "checkpoint": checkpoint,
            "expected": _decide(lambda: verify_inclusion(leaf_digest, proof_doc, checkpoint)),
        })

    inc("legacy_profile", proof["leaf_digest"], proof)
    relabeled = copy.deepcopy(proof)
    relabeled["leaf_digest"]["canonicalization"] = "ACTENON-JCS-STRICT-1"
    inc("current_profile", relabeled["leaf_digest"], relabeled)
    unknown = copy.deepcopy(proof)
    unknown["leaf_digest"]["canonicalization"] = "JSON-LD"
    inc("unknown_profile_label", unknown["leaf_digest"], unknown)

    document = {
        "contract": {"name": "kernel_interop_artifacts", "version": "v1"},
        "reference": {"implementation": "actenon-kernel", "version": _version("actenon-kernel")},
        "countersignature_trusted_keys": cs_keys,
        "approval_trusted_keys": ap_keys,
        "countersignatures": countersignatures,
        "approvals": approvals,
        "inclusions": inclusions,
    }
    ARTIFACTS_OUT.write_text(json.dumps(document, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {len(countersignatures) + len(approvals) + len(inclusions)} artifact cases to {ARTIFACTS_OUT}")


def main():
    for alg in ("hs256", "ed25519"):
        gen_for_alg(alg)
    for case in CASES:
        for sdk, override in case.get("sdk_overrides", {}).items():
            if case["expected"]["outcome"] == "refused" and override["outcome"] == "verified":
                raise SystemExit(f"{case['id']}: an SDK may never accept what the reference refuses")
    ed_pub = Ed25519PrivateKey.from_private_bytes(ED_SEED).public_key().public_bytes_raw()
    document = {
        "contract": {"name": "kernel_interop", "version": "v1"},
        "reference": {
            "implementation": "actenon-kernel",
            "version": _version("actenon-kernel"),
            "protocol_version": _version("actenon-protocol"),
            "verifier": "actenon.verifier.VerifierSDK(disclosure_mode=LOCAL_DEBUG) + actenon.core.json.loads_no_duplicate_keys",
        },
        "signers": {
            "hs256": {"algorithm": "HS256", "key_id": "local-proof-v1", "secret": "actenon-local-proof-secret-v1"},
            "ed25519": {"algorithm": "EdDSA", "key_id": ED_KID, "public_key": b64url_encode(ed_pub)},
        },
        "invalid_input_codes": sorted(INVALID_INPUT_CODES),
        "cases": CASES,
    }
    # One case per line keeps diffs of regenerated vectors reviewable.
    head = json.dumps({k: v for k, v in document.items() if k != "cases"}, ensure_ascii=False, indent=1)
    lines = ",\n".join(json.dumps(case, ensure_ascii=False, separators=(",", ":")) for case in CASES)
    OUT.write_text(head[:-2] + ',\n "cases": [\n' + lines + "\n ]\n}\n", encoding="utf-8")
    print(f"wrote {len(CASES)} cases to {OUT}")
    generate_artifacts()


def _version(dist):
    from importlib.metadata import version
    return version(dist)


if __name__ == "__main__":
    main()
