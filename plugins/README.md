# Collector Plugins

Phase 04 establishes the collector extension point and core ingestion
contracts. Collector-specific implementations are intentionally kept behind
this plugin boundary.

The locked project structure reserves these collector plugin namespaces:

- `plugins/collectors/syslog/`
- `plugins/collectors/linux_auth/`
- `plugins/collectors/nginx/`
- `plugins/collectors/apache/`
- `plugins/collectors/windows/`

Do not couple collector implementations directly to parsing, detection,
correlation, risk, alert, or storage logic.
