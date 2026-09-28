## Summary

<!-- Describe what the change does, why it's needed, and the approach taken. Keep it
short — readers can see the diff. -->

## Planning Checklist
- [ ] Read `CONTRIBUTING.md`
- [ ] Read `docs/plans/active/current-roadmap.md` (if exists)
- [ ] Documented the change before implementation
- [ ] Documentation-first exception: typo, formatting, or mechanical change only

Branch: `{feature|fix|refactor|docs}/<short-name>`

## Domain
- [ ] `aleo-account`
- [ ] `aleo-program`
- [ ] `aleo-execution`
- [ ] `aleo-network`
- [ ] `aleo-client`
- [ ] examples
- [ ] docs

## Validation
Commands run:
```text

```

## Production Boundary
- [ ] Does not touch production boundary
- [ ] API behavior changed
- [ ] Dependency added or upgraded
- [ ] Public API surface changed (breaking change)

## Architecture / Tooling Boundary
- [ ] Uses only `edition = "2024"` Rust
- [ ] Does not introduce new language/toolchain
- [ ] Follows workspace crate structure

## Changelog
- [ ] Not user-visible / not needed
