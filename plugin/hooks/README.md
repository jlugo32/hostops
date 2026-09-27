# hooks/ (intentionally empty in v0.1)

hostops ships no hooks. See `adr/ADR-0005-no-hooks-in-v0.1.md`: a plugin hook
runs arbitrary shell with the user's privileges on every matching event, and a
compromised or malicious plugin update can use hooks (or a settings rewrite) to
disable the very confirmations this project exists to enforce. Safety lives in
the hostops binary (typed commands, confirm tokens, audit log), which a prompt
or plugin update cannot turn off.
