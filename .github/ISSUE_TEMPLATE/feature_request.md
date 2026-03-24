---
name: Feature request
about: Propose a new scanner, playbook, output format, or other enhancement
labels: enhancement
---

## Summary

A one-paragraph description of what you are proposing and why it matters.

## Motivation

What problem does this solve, or what gap in coverage does it address? Who benefits?

## Proposed solution

Describe the feature in enough detail that someone could implement it. For new scanners or playbooks, see the sections below.

## Alternatives considered

Describe any alternative approaches you evaluated and why you ruled them out.

---

## For new scanner proposals

**What vulnerability class or misconfiguration does it detect?**

<!-- e.g. "Detects open Prometheus /metrics endpoints that expose internal application metrics
     and infrastructure topology to unauthenticated clients." -->

**Is this surface (passive) or deep (active probes)?**

- [ ] Surface — only reads publicly observable responses, no payloads
- [ ] Deep — sends crafted payloads, requires `--permission-confirmed`
- [ ] Both — passive discovery in surface mode, active verification in deep mode

**What is the legal / ethical risk profile?**

Deep scanners send requests that may be logged or blocked by the target. Explain why the probe is safe and proportionate for an authorised tester to run.

**Would a Nuclei template cover this, or does it require a custom scanner?**

Nuclei templates are preferred where sufficient. A custom Go scanner is warranted when the check requires stateful logic, multi-step interaction, or data from other scanners as input.

**What playbook(s) should activate this scanner?**

List the technology conditions under which this scanner should run. For universally applicable checks, it may belong in `baseline.yaml`.

---

## For new playbook proposals

**What technology does this playbook target?**

<!-- e.g. "Hashicorp Consul — service mesh and key-value store" -->

**What are the match conditions?**

How can Beacon reliably identify this technology from response headers, body content, or path responses?

```yaml
match:
  any:
    - header_value:
        name: "x-consul-index"
        contains: ""
    - body_contains: "Consul UI"
    - path_responds: "/v1/agent/self"
```

**What are the highest-value checks for this technology?**

List the top 3–5 vulnerabilities or misconfigurations that are common and high impact for this technology, with CVE numbers where applicable.

**Are there technology-specific wordlist paths for deep/directory-bust mode?**

List any paths that should be probed when this technology is confirmed:

```
/v1/agent/self
/v1/kv/?recurse
/v1/acl/tokens
/v1/connect/ca/roots
```

---

## Additional context

Links to relevant CVEs, research, Nuclei templates, or prior art that informed this proposal.
