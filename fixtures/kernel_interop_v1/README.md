# Kernel interop vectors v1

Differential vectors produced by the Python reference verifier
(`actenon-kernel`). Every proof is minted, or for issuer-side edge cases
signed, by the reference, then adversarially mutated (bound fields, clock
boundaries and skew, signature bytes and encodings, algorithm and `kid`
confusion, canonicalisation labels, Unicode and number representations,
duplicate and case-variant JSON members, `null` versus absent members, deep
nesting, sub-second timestamps).

- `cases.json`: Action Intent + PCCB pairs as raw JSON text, the verification
  context, the clock-skew tolerance, and the reference's decision
  (`actenon.verifier.VerifierSDK` with `LOCAL_DEBUG` disclosure, as the
  Kernel's own `verifier_sdk_v1` harness runs it, behind the Kernel's strict
  JSON ingress `actenon.core.json.loads_no_duplicate_keys`). Parse-level
  refusals are compared as the single class `INVALID_INPUT` because each
  implementation reports them with its own code (see `invalid_input_codes`).
- `artifacts.json`: receipt counter-signature, approval-artifact and
  transparency inclusion cases decided by the reference's
  `actenon.verifier` functions.

A case may carry `sdk_overrides` where an SDK is deliberately stricter than
the reference, with the reason. An SDK must never verify a case that the
reference refuses; the generator enforces this.

The same files are vendored, byte-identical, in `sdk-go` and `sdk-rust`.

Regenerate (deterministic output) from a virtualenv with the reference:

```bash
pip install "actenon-protocol>=1.1.0,<2" actenon-kernel==1.2.1
python fixtures/kernel_interop_v1/generate.py
```
