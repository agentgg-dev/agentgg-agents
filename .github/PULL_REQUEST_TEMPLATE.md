### What does this PR do?

<!-- One or two sentences. e.g. "Adds a new agent for detecting JWT signature bypass in Node.js apps." -->

### Type of change

- [ ] New agent
- [ ] Update to existing agent (prompt, patterns, references)
- [ ] Fix (false positive, false negative, broken frontmatter)
- [ ] Docs / tooling only

### Checklist for new or updated agents

- [ ] `agentgg agents lint .` passes
- [ ] Filename matches the `slug:` field
- [ ] `slug:` is unique across the repo
- [ ] `references:` includes a CWE / CVE / OWASP entry if one applies (optional, skip if no clean mapping)
- [ ] `filePatterns:` is as narrow as possible (no scanning .py files for JS-only issues)
- [ ] `noiseTier:` is honest about expected false-positive rate
- [ ] Prompt body has an explicit "false positives — do NOT flag" section
- [ ] Tested locally against a fixture with both vulnerable and patched code

### Test evidence

<!-- Show that you ran it. Paste the scan output, link to a test fixture, or describe what you tried. -->

```
$ agentgg scan ./test-fixture -t ./base/your-category/your-agent.md
```

### References

<!-- CWE / OWASP / CVE / blog posts / advisories that informed this agent -->
