# prime-approval-guardian tracer

This private alpha tracer validates fail-closed Approval Guardian integration with
Prime Agent 0.7.x. It is not the published Prime port and is not a Pi extension.

The default extension intercepts the Prime Agent `ipython` tool and blocks every
cell because no production reviewer is configured yet. Tests inject a deterministic
review decision to verify both allow and block preflight behavior.

## Compatibility

- Prime Agent: `>=0.7.2 <0.8.0`
- Node.js: `>=22.8.0`

## Security scope

This tracer covers only builtin Prime Agent IPython preflight. It does not claim
Pi shell/path-tool coverage, reviewer-model integration, private-data policy, a
sandbox, bypass controls, or grants. Those are delivered by later tickets in #10.

## Native tracer verification

From the repository root, with Prime Agent 0.7.x installed:

```bash
npm run test:prime-native
```

Prime Agent 0.7.x accepts local package directories rather than npm tarball
paths. The smoke test therefore packs the artifact, expands it into an isolated
temporary install, and passes only that installed directory to
`prime-agent package install`. The deterministic provider and working directory
are also copied into the temporary area, so the loaded extension and its runtime
do not resolve from the repository checkout.

It verifies print-mode allow, deny, failure, real deadline timeout, and invalid
review paths, plus RPC blocking and a daemon-backed blocking path. Every blocked
path asserts that the IPython cell did not create its marker file. Versions
outside `>=0.7.2 <0.8.0` fail explicitly.
