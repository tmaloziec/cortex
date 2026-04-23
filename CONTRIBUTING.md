# Contributing to Cortex

Thanks for your interest in contributing! This document explains how to get involved.

## Quick Start

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Make your changes
4. Test locally (`./run.sh agent` and verify)
5. Open a Pull Request
6. Sign the CLA (one click via [CLA Assistant bot](https://cla-assistant.io/))

## Contributor License Agreement (CLA)

Before your Pull Request can be merged, you must sign the [Cortex CLA](CLA.md).

The CLA Assistant bot will automatically prompt you on your first PR. Signing is a one-time action — all your future contributions are covered.

**Why a CLA?** Cortex is dual-licensed (AGPLv3 + commercial). To offer commercial licenses to organizations that need them, the project must hold the rights to all contributed code. Without a CLA, a single contributor could block commercial licensing of the entire project.

The CLA does **not** transfer ownership of your code to anyone. You retain copyright. You simply grant the Maintainer the right to license the project (including your contributions) under multiple licenses.

This is the same model used by Apache Software Foundation, Google, MongoDB, Grafana Labs, and most dual-licensed open source projects.

## What to Contribute

We welcome:

- **Bug fixes** — open an issue first if it's a non-trivial change
- **Plugins** — extend Cortex with new tools and modes (see [Plugin API in README](README.md#plugins))
- **Documentation** — clarifications, examples, translations
- **Tests** — improve coverage of `agent.py`, `policy.py`, etc.
- **Performance improvements** — benchmarks welcome
- **Model compatibility** — testing with new Ollama models

We're cautious about:

- **Major architectural changes** — discuss in an issue first
- **Adding heavy dependencies** — Cortex aims to stay lean
- **Breaking changes to plugin API** — open RFC issue first

## Code Style

- **Python**: PEP 8, 4-space indent, type hints where helpful
- **Naming**: snake_case for functions/variables, PascalCase for classes
- **Comments**: explain *why*, not *what*. Code should be self-documenting
- **No emojis in code** unless functional (e.g. spinner frames)
- **Polish-language comments are welcome** in core files but please use English in plugin examples to keep them accessible

## Plugin Contributions

Plugins live in `plugins/` and are loaded dynamically. Guidelines:

- One plugin per file, named descriptively (e.g. `plugins/web_search.py`)
- Define `PLUGIN_NAME`, `PLUGIN_DESCRIPTION`, `PLUGIN_TOOLS`, `execute_tool()`
- Document any external dependencies in the plugin's docstring
- Avoid network calls without timeout
- Respect the Policy Engine — don't bypass it

See README.md for the full Plugin API.

## Testing

Before submitting:

```bash
# Syntax check
python3 -m py_compile agent.py web.py worker.py policy.py recovery.py compactor.py

# Smoke test
./run.sh agent
> /status
> /exit

# If your change touches tools, test execution
> /policy
> say hello
```

For non-trivial changes, please describe your testing in the PR description.

## Reporting Bugs / Security Issues

- **Bugs**: Open an issue with reproduction steps, environment (OS, Python version, Ollama version, model), and expected vs. actual behavior.
- **Security vulnerabilities**: Do **not** open a public issue. Contact the maintainer privately via [github.com/tmaloziec](https://github.com/tmaloziec) with details. We aim to respond within 7 days.

## Pull Request Checklist

- [ ] CLA signed (CLA Assistant bot will check automatically)
- [ ] Branch from `main`, rebased on latest `main`
- [ ] Code follows existing style
- [ ] Manually tested
- [ ] PR description explains *what* and *why*
- [ ] No private data (IPs, API keys, internal paths) in commits

## Code of Conduct

Be respectful. Disagreements happen — keep them about code, not people. Maintainer reserves the right to lock or close PRs/issues that violate this principle.

## License

By contributing, you agree that your contributions will be licensed under the project's dual license (AGPLv3 + commercial), as described in the [CLA](CLA.md).

---

Questions? Open a [Discussion](https://github.com/build-on-ai/cortex/discussions) or file an issue.
