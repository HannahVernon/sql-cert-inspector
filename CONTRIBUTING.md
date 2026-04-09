# Contributing to sql-cert-inspector

Thank you for your interest in contributing! This document explains how to get started, what we expect from contributions, and how we work together.

## Code of Conduct

This project adopts the [Contributor Covenant Code of Conduct v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to uphold its standards.

**In short:** Be respectful, be constructive, be welcoming. Harassment, trolling, and personal attacks are not tolerated.

Instances of unacceptable behavior may be reported by:

- Opening a [GitHub Issue](https://github.com/HannahVernon/sql-cert-inspector/issues)
- Contacting the maintainer via [GitHub (@HannahVernon)](https://github.com/HannahVernon)

All reports will be reviewed promptly and handled with discretion.

## Getting Started

### Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- Windows (required for Kerberos/SPN diagnostics via `System.DirectoryServices`)

### Building

```bash
git clone https://github.com/HannahVernon/sql-cert-inspector.git
cd sql-cert-inspector
dotnet restore
dotnet build
```

### Running

```bash
dotnet run -- --server myserver
```

### Publishing (self-contained)

```bash
dotnet publish -p:PublishProfile=Properties\PublishProfiles\win-x64.pubxml
```

## How to Contribute

### Reporting Bugs

- Search [existing issues](https://github.com/HannahVernon/sql-cert-inspector/issues) first to avoid duplicates
- Include your OS, app version (`--version`), and SQL Server version
- Redact any server names, IPs, or certificate details you don't want public

### Suggesting Features

Open an issue with the `enhancement` label. Describe the problem you're trying to solve, not just the solution you envision — there may be a better approach.

### Submitting Pull Requests

1. **Fork and branch** from `dev` (not `main`). Use descriptive branch names: `fix/dns-timeout`, `feature/tls13-details`, etc.
2. **Keep changes focused.** One logical change per PR. Don't mix refactoring with feature work.
3. **Build cleanly.** `dotnet build` must produce 0 errors and 0 warnings.
4. **Test your changes.** Verify manually against a SQL Server instance where possible.
5. **Update documentation** if your change affects user-visible behavior, CLI options, or architecture.
6. **Write a clear commit message.** First line is a concise summary; body explains *why*, not just *what*.

## Technical Guidelines

### Code Style

- Target **.NET 9**
- Follow standard C# conventions; the codebase uses file-scoped namespaces, nullable reference types, and implicit usings
- **No commented-out code** in commits
- Comments should explain *why*, not *what*

### Branching

- `dev` — active development branch; PRs target here
- `main` — stable releases only; merges from `dev` via PR
- Feature branches: `feature/xxx`
- Bug fix branches: `fix/xxx`
- Feature branches are deleted after merge

### Versioning

This project uses [MinVer](https://github.com/adamralph/minver) for automatic version derivation from git tags. Version numbers are auto-incremented on merge to main — you do not need to update version numbers manually.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](licence.md) that covers this project.
