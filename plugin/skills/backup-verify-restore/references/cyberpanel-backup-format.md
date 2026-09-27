# CyberPanel backup format (from plogical/backupUtilities.py)

```
backup-example.com-09.27.2026_03-00-00.tar.gz
├── meta.xml            # <metaFile><masterDomain>example.com</masterDomain>…
├── public_html.tar.gz  # site files
└── <database>.sql      # one per database (or .sql.gz)
```

- Created with `tar -czf <backupPath>/<name>.tar.gz -C <tmp> .`, so entries
  start with `./`.
- GUI restore (`dir == "CyberPanelRestore"`) reads `/home/backup/<name>`.
- CLI `restoreBackup --fileName` takes the GUI path when the bare name exists
  in /home/backup, otherwise treats the argument as a full path.
