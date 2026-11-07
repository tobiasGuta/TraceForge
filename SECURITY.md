# TraceForge security policy

TraceForge v0.1 is an **experimental, localhost-only forensic lab tool**.

- **Do not expose it to the internet.** There is no authentication, TLS termination, CSRF defense, per-case authorization, or multi-user isolation.
- The Docker Compose port is bound to \`127.0.0.1\` intentionally.
- Treat all forensic artifacts as hostile. Use a disposable VM or isolated host when analyzing suspicious evidence. The default container is non-root and has \`no-new-privileges\`, but the EVTX parser is not a hardened sandbox.
- Never upload sensitive logs to an untrusted instance. Windows event logs can contain names, account identifiers, paths, command lines, and other personal or confidential information.
- Protect and back up the persistent Docker volume. Deleting the volume destroys case data and evidence.
- Chainsaw is optional and must be installed by the operator. TraceForge uses explicit arguments (no shell) and places time/result limits on runs, but installing third-party binaries/rules still requires independent trust assessment.
- Built-in findings are triage observations and not proof of compromise. Validate every claim using original evidence.

To report a vulnerability, use GitHub's private vulnerability reporting feature if it is enabled for this repository; otherwise contact the repository owner privately rather than publishing sensitive exploit details in an issue.
