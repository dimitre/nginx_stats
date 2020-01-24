# NGINX STATS


select COUNT(*) AS NUM, *  FROM logs where c2 like 'http://dmtr%' GROUP BY c1 ORDER BY NUM DESC




clone inside access logs folder, in my case /var/log/nginx
rund directly from command line
```
cd /var/log/nginx/nginx_stats
./nginx5.py
```

