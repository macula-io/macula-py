# Signature fixtures

Copied byte for byte from macula-ts v0.20.0's `test/fixtures/`, which carries
them from macula v12.7.0 (the same bytes macula-go pins).
`tests/test_signatures.py` pins each by sha256.

- `lamps_mldsa87_rsa4096_pss_sha512/`: the LAMPS draft's own vector for
  id-MLDSA87-RSA4096-PSS-SHA512, the composite pq_hybrid signs with
  (`src/testvectors.json` of lamps-wg/draft-composite-sigs at
  `f0627ab34acfe1aee0abce4bee91ed2b577eab76`). `m.bin` message, `pk.bin`
  public key, `sk.bin` private key, `s.bin` signature with the empty context,
  `s_with_context.bin` with `ctx.bin`.
- `lamps_composite_zero_dropped/sig.bin`: a composite by the draft's key whose
  RSA-PSS half lost its leading zero byte. Every stack must refuse it.
- `macula_12_cross/macula_signed/`: a pq_hybrid composite macula 12 signed with
  a key of its own (`m.bin`, `pk.bin`, `s.bin`).

# Proof and UCAN vectors

Pinned by sha256 in `tests/test_proofs.py` and `tests/test_ucan.py`.

- `device_request/message.hex`: the realm's device request proof v2 message
  (macula-realm#29) for the inputs `test_proofs.py` names, from macula-go
  v0.17.0's `devicerequest/testdata/device_request_proof_vector.hex`.
- `ownership_proof/message.hex`, `identity.hex`: mcl_om 0.32.0's
  `message/6` for the inputs `test_proofs.py` names, and the identity it was
  made for, from macula-go v0.17.0's `ownershipproof/testdata/vector`.
- `ucan/ucan_v1.json`: macula's UCAN vectors, `test/vectors/ucan_v1.json` at
  `0e2724cc97a5689542b8da7b06d392cf0d34b205` (`UCAN_V1.md` beside it there is
  the contract).
