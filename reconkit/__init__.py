"""reconkit - evidence-driven, scope-aware attack-surface recon pipeline.

Every stage module in this package follows the same contract:
  - never raises an exception that escapes to the caller for *expected*
    failure modes (missing tool, timeout, empty result) - those are
    recorded as a tool_run status in SQLite instead;
  - treats all tool output (and all scanned-target output) as untrusted
    data: no eval, no shell=True with interpolated strings, filenames are
    sanitized before touching the filesystem;
  - writes raw tool output under raw/<run_id>/<stage>/ before any
    normalization, so every normalized row can be traced back to its
    source bytes;
  - only ever probes hostnames that reconkit.scope.Scope says are in
    scope; anything else is recorded as a third_party_observation and
    skipped.
"""

__version__ = "1.0.0"
