# Security Policy

## Supported Versions

RuleForge is currently in active academic development. Only the latest commit on
the `main` branch receives security fixes.

| Version | Supported |
|---------|-----------|
| Latest (`main`) | Yes |
| Older releases / tags | No |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately via
[GitHub's private vulnerability reporting](https://github.com/dangel34/Compliance-Scanner/security/advisories/new).

Include as much of the following as possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- The affected file(s) and line numbers if known
- Your suggested fix or mitigation (optional)

We aim to acknowledge reports within **72 hours** and provide an initial assessment
within **7 days**. Given that this is a noncommercial academic project, full patches
may take longer depending on team availability.

## Security Model

RuleForge is a **local compliance scanner**. It reads rule files from disk, executes
read-only system inspection commands, and writes reports. There is no network server,
no authentication system, and no persistent user data store.

Key design decisions relevant to security:

- **Rule file sandbox** — `core/rule_runner.py` maintains an explicit allowlist
  (`_ALLOWED_CF_MODULES`) of the custom-function modules that rule files may reference.
  Any module name not on the allowlist is rejected before `importlib.import_module` is
  called, preventing crafted rule files from loading arbitrary Python modules.

- **Shell injection prevention** — Scanner modules (`core/scanners/windows.py`,
  `core/scanners/debian.py`) reject service names and file paths containing shell
  metacharacters (`'`, `"`, `;`, newlines, etc.) before use in commands.

- **PowerShell command isolation** — PowerShell commands are passed as list arguments
  with `shell=False` where possible, so the Windows command interpreter cannot
  reinterpret pipe characters or special characters embedded in command strings.

- **Temporary file hygiene** — Functions that write `secedit` exports use unique
  `uuid4`-based temp paths and clean up via `finally` blocks.

- **ReDoS prevention** — RFC-1918 subnet checks use `ipaddress.ip_address().is_private`
  instead of a complex regex, eliminating potential catastrophic backtracking.

- **Dependency pinning** — Runtime and development dependencies are pinned in
  `uv.lock` to reduce supply-chain risk.

## Threat Model

RuleForge is designed to be run by an **IT administrator on their own machine** to
assess local compliance posture. The primary threats considered are:

| Threat | Mitigation |
|--------|-----------|
| Malicious rule file (crafted `.json`) loading arbitrary code | `_ALLOWED_CF_MODULES` allowlist in `rule_runner.py` |
| Shell injection via scanner inputs | Metacharacter rejection in scanner modules |
| Symlink / path-traversal in rule directory loading | `os.path.realpath` checks in `final_gui.py` |
| Stale transitive dependency with known CVE | `uv.lock` pins all 22+ transitive packages |

## Out of Scope

The following are **not** considered vulnerabilities in RuleForge's threat model:

- An administrator deliberately placing a malicious rule file in the rulesets directory
  (this is equivalent to running arbitrary code as that user already)
- Scan results that differ from a manual audit (the tool is a decision-support aid,
  not a compliance authority)
- False positives or false negatives in compliance checks
- Use of the tool with elevated privileges on a system the user does not own or
  administer

## License

This project is released under the
[PolyForm Noncommercial License 1.0.0](LICENSE). Security findings in this
codebase may be disclosed publicly after a patch has been released or after
90 days from the date of the initial private report, whichever comes first.
