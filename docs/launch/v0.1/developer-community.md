# Developer community post — draft

**Subject:** Drifti v0.1 — capability contracts from real agent runs (Linux)

If you ship coding agents or automation that touches the filesystem, subprocesses, or network, you’ve probably felt the gap between “it worked once” and “what is it allowed to do next time?”

**Drifti** closes part of that gap:

1. **Observe** a run under Linux ptrace (`drifti observe -- …`)
2. **Learn** a capability profile from stored evidence
3. **Generate** a proposed `drifti.yaml` (you review before trusting)
4. **Verify** later runs against that contract; **diff** when behavior changes

The model is intentional: observation ≠ authorization. Contracts are proposals until a human accepts them. Policy evaluation is deterministic—no model approves capabilities.

**v0.1 caveats:** Linux x86_64 binary + source builds; incomplete observation coverage is surfaced honestly (verify exit 122). Not macOS observation yet.

Try it: https://github.com/lucabecci/drifti  
Docs: https://github.com/lucabecci/drifti/blob/main/docs/linux/README.md

Questions and PRs welcome.
