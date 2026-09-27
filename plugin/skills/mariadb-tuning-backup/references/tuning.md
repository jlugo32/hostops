# MariaDB 11 on a small VPS (8 GB, shared with OLS/lsphp)

| Setting | Starting point | Note |
|---|---|---|
| innodb_buffer_pool_size | 1–2G | leave RAM for lsphp children |
| max_connections | 100 | each PHP child can hold one |
| long_query_time | 1 | seconds; slow log only |
| slow_query_log_file | slow.log | relative to datadir |
| innodb_log_file_size | 256M | larger = fewer checkpoints |

Memory budget: buffer pool + (max_connections × ~3 MB) + lsphp
(LSAPI_CHILDREN × memSoftLimit worst case) must stay under physical RAM, or the
OOM killer picks lsphp or mariadbd.

Fingerprints: hostops replaces literals with `?` and IN lists with `(?+)` so
`WHERE email='a'` and `WHERE email='b'` group together.
