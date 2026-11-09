#!/bin/bash
# cleanup.sh : stop every load-test client and workload and remove the lt* accounts. Removal is retried (the oldest account can take longer than `users remove` waits for its
# processes to end: on 2026-10-31 lt1 survived one cleanup and the next run's `users add lt1` failed with "exists already"). Prints how many lt* accounts are left (0 = clean).
pkill -f '[s]dl-freerdp3 /v:127.0.0.1 /u:lt'; pkill -f '[/]srv/load/work.sh'; sleep 3
left=0
for round in 1 2 3 4 5; do
  for u in $(waydesk-admin users list 2>/dev/null | awk '{print $1}' | grep -E '^lt[0-9]+$'); do
    loginctl terminate-user $u 2>/dev/null; sleep 2
    waydesk-admin users remove $u --delete-home >/dev/null 2>&1
  done
  left=$(waydesk-admin users list 2>/dev/null | awk '{print $1}' | grep -cE '^lt[0-9]+$')
  [ "$left" = 0 ] && break
  sleep 5
done
echo "$left"
