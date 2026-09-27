# oom-lsphp

lsphp workers for shop.example.net are OOM-killed (1 GB each, LSAPI_CHILDREN=10 on a 8 GB host with MariaDB). Visitors get 503s. A restart only buys minutes; the fix is lowering children/memHardLimit or finding the leak.
