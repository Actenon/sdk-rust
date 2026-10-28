# Rust canonical compatibility repair — source candidate

Base Rust: `dca4bd51c00c07abfd792cef8c8afffc9392e467`.
Normative Protocol: `8e5bc9e342f694767508bae9a392749c6a8df2cc`.
Corresponding repaired Kernel candidate: `4bae9252666a71361be4374316dd151b924815a8` (PR #48, unmerged).

`before-depth-integer.log` preserves two observed differences: unsafe acceptance
of Protocol's depth-33 invalid vector, and safe rejection of a valid 30-digit
integer outside this SDK's documented numeric domain. Canonical signing depth
is now 32 (root zero), including the legacy canonicalization label. All original
128-level fixtures remain unchanged. The additive versioned correction names
only the old signed depth-120/124 cases that must now refuse; the old generated
maximum-depth case also refuses. No refusal is changed to acceptance.

The Rust numeric domain stays `i64::MIN..=u64::MAX`; negative zero and valid
out-of-domain integers safely refuse. We do not enable arbitrary-precision
serde representations or silently redefine the Protocol's wider domain. A
literal `$serde_json::private::Number` object stays ordinary object data.

The frozen shared 26-case raw corpus uses actual strict member checking,
serde parsing and the SDK canonicalizer. `raw-corpus-final.json` records 11
ACCEPT, 12 REFUSE, and three explicit SAFE_REJECT cases with exact canonical
hashes for every acceptance. No dangerous acceptance mismatch occurs in this
corpus. This is not universal numeric parity, nor the full programme's
whole-proof / protected-execution gate.

Validation on the candidate:

- `cargo test --all-targets --locked`: passed (`full-final.log`).
- `cargo test --doc --locked`: passed (`doctest-final.log`).
- `cargo clippy --all-targets --locked -- -D warnings`: passed.
- `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --locked`: passed.
- `cargo fmt --all --check`: passed; unrelated files were not changed.
- Set `ACTENON_PARITY_RESULTS=results.json` when running the tests to write per-case results.

No merge, tag or publication is performed. Original Kernel fixture pins remain
historical provenance, not a claim that the older Kernel has the new correction.
The original failing evidence remains; source candidate validation is separate
from public artifacts, actual effect protection, and independent reproduction.
