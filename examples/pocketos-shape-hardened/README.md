# The same agent, hardened

Three changes. No new framework, no model swap, no rewrite.

1. **`run_shell` deleted.** A shell tool inherits every credential in the
   environment, which makes the declared surface unbounded no matter how
   carefully you write the rest of the manifest.

2. **The remaining state changes are gated.** `redeploy_service`, `set_env_var`,
   and outbound Slack now say so in the description, and the scanner reads that.
   A gate is a 90% discount in the score, never 100%, because people approve
   things at 2am.

3. **No credentials on disk.** There is deliberately no `.env` in this directory.
   Credentials are issued per call, scoped to one resource, and expire. The agent
   cannot find what is not there.

Run both and compare:

```bash
python -m blast_radius examples/pocketos-shape          --manifest examples/pocketos-shape/agent-tools.json
python -m blast_radius examples/pocketos-shape-hardened --manifest examples/pocketos-shape-hardened/agent-tools.json
```

The number that should move is not the score. It is the count of things that can
happen in nine seconds and never come back.
