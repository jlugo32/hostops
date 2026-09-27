# mariadb-slow-query

shop.example.net checkout is slow. The slow log shows one query fingerprint (orders by customer_email, 2.5M rows examined) dominating. The fix is an index, not a MariaDB restart.
