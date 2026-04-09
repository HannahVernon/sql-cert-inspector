# Copilot Instructions — sql-cert-inspector

## Documentation Sync Rule

Whenever you make a code change that affects any of the following, you **must** update the corresponding documentation files in the same commit:

| What changed | Update these files |
|---|---|
| New/renamed/removed files or folders | `ARCHITECTURE.md` (file tree + relevant sections) |
| New/changed CLI options or behavior | `README.md` |
| Build requirements, project structure | `README.md`, `CONTRIBUTING.md` |
| New NuGet dependencies | `licence.md` (package name, version, copyright, license) |

**Do not defer documentation updates to a follow-up commit.** Treat docs as part of the definition of done for every change.

## GitHub Issue Linking

Before starting work on a bug fix or feature, search the repository's GitHub Issues to see if a matching issue already exists. If one exists, reference it in your PR (e.g., `Fixes #123` or `Closes #123`) so it is automatically closed when the PR merges. If no matching issue exists, create one first with a clear title and description, then link it to your PR the same way.

When creating issues via `gh issue create`, structure the body to match the repository's YAML issue templates in `.github/ISSUE_TEMPLATE/`:

- **Feature requests** (`feature_request.yml`): include sections for "Problem or use case", "Proposed solution", "Alternatives considered", and "Additional context".
- **Bug reports** (`bug_report.yml`): include sections for "Describe the bug", "Steps to reproduce", "Expected behavior", "Actual output", "Operating system", ".NET version", "SQL Server version", and "sql-cert-inspector version".

Use `###` headings for each section to mirror the template field labels.

## NuGet Vulnerability Scanning

Whenever a NuGet package is added, updated, or its version changes, run `dotnet list package --vulnerable` from the solution root and verify zero vulnerabilities before committing. If a vulnerability is found, check for a patched version or flag it to the user for a decision.
