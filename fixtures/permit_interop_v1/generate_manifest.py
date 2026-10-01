"""Record the Python reference's decisions for the Permit-minted artefacts.

Each directory holds a PCCB minted through actenon-permit by actenon-kernel
(Ed25519 from the Permit issuer key, or the public local HS256 key), the
Action Intent it was minted for, and a widened copy of that intent. The
decision is actenon.verifier.VerifierSDK (LOCAL_DEBUG disclosure) at
now = pccb.issued_at for the audience the proof names.

    pip install "actenon-protocol>=1.1.0,<2" actenon-kernel==1.2.1
    python fixtures/permit_interop_v1/generate_manifest.py
"""

from __future__ import annotations

import base64
import json
import warnings
from dataclasses import dataclass
from pathlib import Path

warnings.simplefilter("ignore")

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

from actenon.core import ProofVerificationError  # noqa: E402
from actenon.models import AudienceRef  # noqa: E402
from actenon.models.contracts import SignatureSpec, parse_timestamp  # noqa: E402
from actenon.proof import VerifierDisclosureMode, build_local_proof_signer  # noqa: E402
from actenon.verifier import VerifierSDK  # noqa: E402

ROOT = Path(__file__).resolve().parent


def _b64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True)
class JwkVerifier:
    """EdDSA verification as actenon.proof.signers.well_known performs it."""

    jwk: dict
    algorithm: str = "EdDSA"

    @property
    def key_id(self) -> str:
        return self.jwk["kid"]

    def verify(self, payload: bytes, signature: SignatureSpec) -> bool:
        if signature.algorithm != "EdDSA" or signature.key_id != self.key_id or signature.encoding != "base64url":
            return False
        try:
            Ed25519PublicKey.from_public_bytes(_b64(self.jwk["x"])).verify(_b64(signature.value), payload)
        except (InvalidSignature, ValueError):
            return False
        return True


def decide(directory: Path, intent_name: str) -> dict:
    pccb = json.loads((directory / "pccb.json").read_text(encoding="utf-8"))
    jwk_path = directory / "public_key.jwk.json"
    signer = JwkVerifier(json.loads(jwk_path.read_text(encoding="utf-8"))) if jwk_path.exists() else build_local_proof_signer()
    sdk = VerifierSDK(signer, disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG)
    context = sdk.build_context(
        request_id="req_permit_interop",
        audience=AudienceRef.from_dict(pccb["audience"]),
        now=parse_timestamp(pccb["issued_at"], "issued_at"),
        scope_capabilities=tuple(pccb["scope"]["capabilities"]),
    )
    intent = json.loads((directory / intent_name).read_text(encoding="utf-8"))
    try:
        sdk.verify(intent=intent, pccb=pccb, context=context)
    except ProofVerificationError as exc:
        return {"outcome": "refused", "reason_code": exc.refusal_code}
    return {"outcome": "verified"}


def main() -> None:
    cases = []
    for directory in sorted(path for path in ROOT.iterdir() if path.is_dir()):
        for intent_name in ("action_intent.json", "action_intent_widened.json"):
            cases.append({
                "id": f"{directory.name}/{intent_name}",
                "directory": directory.name,
                "intent": intent_name,
                "expected": decide(directory, intent_name),
            })
    (ROOT / "manifest.json").write_text(json.dumps({"cases": cases}, indent=1) + "\n", encoding="utf-8")
    for case in cases:
        print(case["id"], case["expected"])


if __name__ == "__main__":
    main()
