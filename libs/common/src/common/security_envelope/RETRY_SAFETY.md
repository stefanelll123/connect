# RETRY SAFETY: JTI Uniqueness Requirement Per Retry

## Rule

**Every retry attempt MUST generate a new `jti` (UUID v4).**

The `jti` claim is the replay-prevention token in the SentinelProof JWT.  
The producer stores every received `jti` in a replay cache with TTL = `exp - iat + max_clock_skew`.

If the consumer reuses the same `jti` on a retry, the producer will reject it with `REPLAY_DETECTED (401)`.

## VP Binding

The VP is bound to the proof via `nonce == jti`:

```
VP.nonce  ==  ProofClaims.jti
```

Because the `jti` changes per retry, **the VP must also be rebuilt** for each attempt.

## Consumer Pipeline Contract

The `OutboundPipeline` is responsible for:

```python
for attempt in range(max_retries):
    jti = str(uuid4())                    # NEW per attempt
    vp  = create_vp(..., nonce=jti)        # VP bound to this jti
    proof_jwt, _ = builder.build(..., jti=jti)
    # ... send request
```

Never cache or reuse:
- `jti`
- The `proof_jwt` string
- The `vp_jwt` string

## Rationale

Proof JWTs expire within 60 s.  Even if the first attempt timed out before
the producer processed it, there is no safe way to know whether the producer
already committed the `jti` to its replay cache.  Generating a fresh `jti`
is the only safe approach.
