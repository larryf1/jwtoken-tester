# Vendored `github.com/conventionalcommit/parser`

Vendored copy of [`conventionalcommit/parser`](https://github.com/conventionalcommit/parser)
**v0.8.0** (MIT, see `LICENSE.md`), used via a `replace` directive in the root
`go.mod`:

```go
replace github.com/conventionalcommit/parser => ./third_party/conventionalcommit-parser
```

## Why

Upstream `parser` v0.8.0 crashes with `panic: runtime error: index out of range
[-1]` (in `parser.bodyState` → `lexer.Rewind` → `popRune`) when a commit message
has **both a body and a `BREAKING CHANGE:` / `BREAKING-CHANGE:` footer** — the
common shape for breaking-change commits. That panic fails `make lint-commits`
and the CI `lint-commits` job for otherwise valid messages. There is no fixed
upstream release to pin (v0.8.0 is the latest).

## The patch

The bug is in `checkIfFooterToken` (`lexer_state.go`): on a `BREAKING CHANGE`
match it called `Emit(breakingChangeToken)`, which resets `startPos` and clears
the rewind stack while an enclosing token (the body, or the previous footer's
value) is still open. Callers then `rewind()` past the now-empty stack.

- `lexer.go`: added `emitZero`, which pushes a zero-length token without
  touching `startPos` or the rewind stack.
- `lexer_state.go`: `checkIfFooterToken` now reports `breakingChangeToken` with
  `emitZero` instead of `Emit`.

Token stream and parsed `Commit` results are identical to upstream for every
message upstream can parse (all upstream tests pass unchanged), and two
upstream value-corruption cases (a footer value directly before a
`BREAKING CHANGE` footer) are fixed as a side effect.

## Tests

The upstream test suite is included. Run it with:

```sh
go -C third_party/conventionalcommit-parser test ./...
```

(`make test` does this.) `parser_breaking_body_test.go` is the local regression
test for the panic above; the rest is unmodified upstream code.

## Updating

To move to a newer upstream release, replace the `*.go` files with the new
version, re-apply the two-line patch described above, and run the test suite.
Delete this `replace` once upstream ships a release that parses
body + `BREAKING CHANGE` footers without panicking.
