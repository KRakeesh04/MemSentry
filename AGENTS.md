# AGENTS.md

## Project
Local desktop application for automated memory forensics analysis using Volatility 3.

## Tech Stack
- Python 3
- PySide6
- Volatility 3
- SQLite
- Pydantic
- Jinja2
- pytest

## Development Rules
- Keep code modular and readable.
- Follow the existing project structure.
- Use type hints where practical.
- Avoid unnecessary dependencies.
- Do not hardcode file paths or configuration.
- Handle errors with clear messages.
- Add comments only where logic is not obvious.

## Documentation Rules
- Do not create large or detailed documentation files by default.
- Only create a documentation file when explicitly asked.
- Do not create documentation just to describe changes you made.
- All documentation files must be created inside the `docs/` directory.
- Prefer updating an existing relevant document if possible instead of creating a new one.

## Forensic Rules
- Never modify the original memory dump.
- Treat evidence as read-only.
- Calculate SHA-256 hashes for evidence.
- Verify evidence integrity before/after analysis.
- Record important analysis actions for auditability.
- Keep analysis results reproducible.

## Acquisition
- Live memory capture is stretch work, not MVP. Scaffold: `src/memsentry/acquisition/`.
- Keep acquisition separate from `volatility/`. Dump tools write a raw file; Volatility only analyses that file afterwards.
- Write captured images into the case directory. Hash the file (SHA-256) before analysis. Never modify the captured image.
- Use a fixed, approved dump tool per OS adapter. Do not run arbitrary user shell commands.

## Volatility
- Use Volatility 3 through the project's wrapper/adapter.
- Do not scatter direct Volatility calls across the codebase.
- Plugin execution should go through the plugin runner.
- Handle missing symbols and unsupported plugins gracefully.
- Support Windows, Linux, and macOS where Volatility supports them.

## Database
- Use the database layer instead of direct SQLite calls.
- Store case/evidence metadata, hashes, analysis runs, plugin results, and audit information.
- Do not store entire memory dumps in the database.

## Testing
- Add tests for important logic.
- Never use real sensitive evidence in tests.
- Use sample/test memory images where necessary.
- Do not remove existing tests just to make changes pass.
- Do not run any random scripts without permission.
- Raise a warning before running scripts if you detect it is a red flag.

## Before Making Changes
- Understand the existing implementation first.
- Make the smallest necessary change.
- Do not rewrite unrelated code.
- Preserve backward compatibility where practical.

If context file available in [context.md](./docs/PROJECT_CONTEXT.md) refer that for project context and make the changes accordingly and update the context in that file. Do not create the file if not available.

Refer the [REQUIREMENTS.md](./docs/REQUIREMENTS.md) for the project requirements.