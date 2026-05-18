# govuln-tui

Interactive terminal UI for [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) results.

## Install

```
go install github.com/binary-buxxe/vulncheck-tui@latest
```

Requires `govulncheck` on your `PATH`:

```
go install golang.org/x/vuln/cmd/govulncheck@latest
```

## Usage

Run from the root of any Go module:

```
govuln-tui              # scans ./...
govuln-tui ./pkg/...    # scans specific packages
```

## Color legend

| Color  | Meaning |
|--------|---------|
| 🔴 Red    | **Called** — your code has a call stack into the vulnerable function. Fix immediately. |
| 🟠 Orange | **Package** — you import the affected package but don't call the vulnerable symbol. |
| 🟡 Yellow | **Module** — the module is in `go.mod` but you don't import the affected package. |
| ⚫ Grey   | **Info** — in the OSV database; not found in your dependency graph. |

## Keyboard shortcuts

| Key | Action |
|-----|--------|
| `↑` / `↓` / `j` / `k` | Navigate list |
| `/` | Filter vulnerabilities |
| `r` | Rescan |
| `?` | Color legend & shortcuts |
| `q` / `esc` | Quit |

## Ignoring vulnerabilities

Create a `.govulnignore` file in your module root to suppress specific findings:

```
# suppress known false positives
GO-2024-1234
GO-2024-5678
```

Lines starting with `#` are treated as comments.
