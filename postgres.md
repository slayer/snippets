# PostgreSQL

## WAL corruption
```
2017-11-14 00:15:33 UTC [17081-1] LOG:  started streaming WAL from primary at 236/F4000000 on timeline 1
2017-11-15 06:25:48 UTC [18911-2] LOG:  received fast shutdown request
2017-11-15 06:25:48 UTC [18911-3] LOG:  aborting any active transactions
2017-11-15 06:25:48 UTC [17081-2] FATAL:  terminating walreceiver process due to administrator command
2017-11-15 06:25:59 UTC [18914-1] LOG:  shutting down
2017-11-15 06:25:59 UTC [18914-2] LOG:  database system is shut down
2017-11-15 06:26:00 UTC [12889-1] LOG:  database system was shut down in recovery at 2017-11-15 06:25:59 UTC
2017-11-15 06:26:00 UTC [12889-2] LOG:  entering standby mode
2017-11-15 06:26:00 UTC [12889-3] LOG:  redo starts at 23A/1046B088
2017-11-15 06:26:01 UTC [12889-4] LOG:  consistent recovery state reached at 23A/11F93FF8
2017-11-15 06:26:01 UTC [12888-1] LOG:  database system is ready to accept read only connections
2017-11-15 06:26:01 UTC [12889-5] FATAL:  invalid memory alloc request size 1380671488
2017-11-15 06:26:01 UTC [12888-2] LOG:  startup process (PID 12889) exited with exit code 1
2017-11-15 06:26:01 UTC [12888-3] LOG:  terminating any other active server processes
```

solution: increase WAL on master, resync slave


## Processes/Queries/Locks

list of active queries
```
SELECT user, pid, client_addr, waiting, query, query_start, NOW() - query_start AS elapsed
FROM pg_stat_activity
WHERE query != '<IDLE>'
-- AND EXTRACT(EPOCH FROM (NOW() - query_start)) > 1
ORDER BY elapsed DESC;
```

waiting:
```
SELECT user, pid, client_addr, waiting, query, query_start, NOW() - query_start AS elapsed
FROM pg_stat_activity
WHERE query != '<IDLE>'
 AND waiting = 't'
ORDER BY elapsed DESC;
```
