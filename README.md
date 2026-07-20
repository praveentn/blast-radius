# blast-radius

Score what an AI agent could destroy before anyone can stop it.

Most agent security checklists audit the tools you granted. The expensive
incidents come from a credential the agent **found**. This scans both.

```
declared   the tools you handed it            (--manifest)
ambient    the credentials it can reach       (the working tree, --env)
```

No dependencies. Python 3.9 or newer.

## Run it

```bash
git clone <your fork>
cd blast-radius

# score an agent that runs in ./my-project with a given tool manifest
python -m blast_radius ./my-project --manifest tools.json

# include the credentials in your own shell environment
python -m blast_radius . --manifest tools.json --env

# machine readable
python -m blast_radius . --manifest tools.json --json
```

### The worked example

`examples/pocketos-shape/` is a deploy-helper agent. Look at its manifest first.
Ten capabilities, all reasonable, and **no delete tool anywhere in the file**.

```bash
cp examples/pocketos-shape/.env.example examples/pocketos-shape/.env
python -m blast_radius examples/pocketos-shape \
  --manifest examples/pocketos-shape/agent-tools.json
```

```
 SEVERE   score 175

 What this agent can do in 9 seconds, permanently
   x deploy.run_shell                                    via declared
   x database: irreversible via DATABASE_URL             via ambient (.env)
   x Railway: irreversible via RAILWAY_DOMAIN_TOKEN      via ambient (.env)

 Authority gaps
 the name reads narrow, the credential is not
   ! RAILWAY_DOMAIN_TOKEN  (.env)
     actually reaches: whole-account GraphQL API including volume and service deletion
```

Three permanent actions, from a manifest whose most dangerous-sounding verb is
"redeploy."

Now the same agent with three changes (shell tool deleted, remaining state
changes gated, credentials off disk and issued per call):

```bash
python -m blast_radius examples/pocketos-shape-hardened \
  --manifest examples/pocketos-shape-hardened/agent-tools.json
```

```
 CONTAINED   score 2

 What this agent can do in 9 seconds, permanently
   nothing irreversible is reachable ungated
```

175 to 2. No rewrite, no model change, no new framework.

## How the score works

Five tiers, ordered by how hard the damage is to undo, not by how alarming the
name sounds. A tool that spends money outranks one that edits a row, because the
row has a previous value and the money does not.

| Tier | Weight | Meaning |
|---|---|---|
| `irreversible` | 40 | cannot be undone |
| `spending` | 15 | costs real money |
| `exfiltrating` | 12 | leaves the building |
| `mutating` | 4 | reversible with effort |
| `readonly` | 0 | safe |

Two modifiers:

- **Gated** (the description says a human confirms first) cuts the weight by 90%.
  Never 100%. People approve things at 2am.
- **Recoverable** (soft delete, versioning, retention) halves it.

Bands: `CONTAINED` < 40, `NOTABLE` < 120, `SEVERE` < 250, `UNBOUNDED` above.

**The score is not the point.** The number to watch is the count under
"what this agent can do in 9 seconds, permanently." A score of 300 made entirely
of read and spend operations is a budget problem. A score of 45 with one ungated
irreversible capability is a resume-generating event.

### Three opinions baked in

1. **An unrecognised verb is treated as mutating, not safe.** Defaulting unknown
   capability to harmless is how you get a nine second outage.
2. **A shell tool is irreversible by definition.** `run_shell` inherits every
   credential in the environment, so the declared surface is unbounded no matter
   how careful the rest of the manifest is.
3. **A found credential is never gated.** If the agent discovers it, nothing is
   standing between the reasoning and the API.

### Authority gaps

The check worth running on its own. It flags credentials whose **name reads
narrow** while the provider grants broad authority. `RAILWAY_DOMAIN_TOKEN` reads
like it manages domains. Railway account tokens are not scoped per resource.

Every human who reviewed that line assumed the scope was domains.

## Use it in CI

```bash
python -m blast_radius . --manifest tools.json --fail-on-irreversible
python -m blast_radius . --manifest tools.json --fail-over 120
```

Both exit `1` when the threshold trips, so a pull request that widens an agent's
authority fails the build instead of being discovered during an incident.

## Manifest formats

Three shapes, all accepted:

```json
{"mcpServers": {"deploy": {"tools": [{"name": "read_logs", "description": "..."}]}}}
{"tools": [{"name": "read_logs", "description": "..."}]}
["read_logs", "delete_volume"]
```

Descriptions matter. That is where the gate and recoverability language lives.

## Tests

```bash
python tests/test_classify.py
```

## Limits, stated plainly

- It reads names and descriptions. It does not call your provider to enumerate
  what a token can really do, so `PROVIDER_AUTHORITY` in `scanner.py` is a
  curated guess per provider. Extend it for your stack.
- A manifest is not runtime. Agents acquire authority at runtime through shells,
  subprocesses, and fetched content. `run_shell` is treated as unbounded for
  exactly this reason.
- It cannot see prompt injection. It measures what damage is possible, not how a
  model is talked into it. Both matter, this covers one.
- Gate detection reads English in the description. If your gates live in code,
  the score will read worse than reality. That direction is the safe one.

## License

MIT
