# Production Detection Engineering Designs

These are Splunk Enterprise Security correlation-search starting points,
not validated production detections. Replace index=botsv3 with production
indexes or accelerated CIM data models. Validate field mappings and the
lookup in the target ES version before enablement. The SPL is in the
queries directory; fixtures are in tests/fixtures.

## Shared operating model

| Setting | Value |
|---|---|
| Schedule | Every 5 minutes, cron */5 * * * * |
| Time basis | Index Time in the ES correlation search to catch delayed ingestion; measure actual p95/p99 lag and adjust |
| Grace/lookback | Rule 1/2: earliest=-15m latest=-5m. Rule 3: earliest=-20m latest=-5m. Latest=-5m supplies the requested 5-minute grace |
| Overlap | Five-minute cadence overlaps the lookback ranges; the rules must be idempotent |
| Dedup/throttle | Use the per-rule key below and configure a 60-minute throttle in ES |
| Trigger | At least one result; risk modifiers for user/system entities; notable only at the enterprise aggregate risk threshold |
| Ownership | Set owner, service owner, runbook, review date, escalation queue, and severity before enabling |
| Validation | Pair each synthetic positive/negative fixture with an expected fire/no-fire result; no fixtures have been run in Splunk |

ES supports event-time or index-time correlation search ranges,
throttling, and multiple risk modifiers. An event-time-only schedule can
miss late events after a window has already run. Use index-time selection,
overlap, and deduplication, then tune to measured ingestion delay.
[Correlation search scheduling and time basis](https://help.splunk.com/en/splunk-enterprise-security-7/administer/7.3/correlation-searches/configure-correlation-searches-in-splunk-enterprise-security),
[risk modifiers](https://help.splunk.com/en/splunk-enterprise-security-7/administer/7.3/correlation-searches/configure-adaptive-response-actions-for-a-correlation-search-in-splunk-enterprise-security).

## Required field contract

| Source | Fields the SPL expects | CIM-facing outputs |
|---|---|---|
| CloudTrail S3 management | bucket, acl_grantee_uri (multi-value), policy_public_principal (boolean), eventID, eventName, errorCode, userIdentity.userName/arn, sourceIPAddress | user, src, dest=bucket, action, vendor_product, signature |
| Windows Security 4720/4732 | EventCode, SubjectUserName, TargetSid/TargetUserName, MemberSid/MemberName, GroupSid/GroupName, host | user=target account, user_id=target SID, creator/modifier fields, dest=host, signature |
| Sysmon 1/3 | EventCode, ProcessGuid, Image, ParentImage, CommandLine, User, DestinationIp, DestinationPort, host | user, dest=host, process_guid, process_name, process_path, parent_process_name, command_line, dest_ip, dest_port, transport |

Normalize CloudTrail ACL grantee URIs and public policy principals before
the scheduled search. A bucket policy is public when its parsed Principal
is wildcard, including a wildcard AWS principal. Do not infer a public
grant from PutBucketAcl alone. Group and user fields vary across the
Windows add-on; validate the raw event aliases. Sysmon Event 3 must be
enabled and ProcessGuid populated.

## Rule metadata

| Rule | ID / severity | Schedule and range | Dedup key | Risk objects and scores | False-positive tuning |
|---|---|---|---|---|---|
| Public S3 ACL or policy | BOTSV3-CLOUD-S3-PUBLIC-ACL-001 / High; Critical only for sensitive asset or verified data access | */5 * * * *; -15m to -5m; 5m grace; Index Time | CloudTrail eventID; fallback bucket + actor + eventName + event time; throttle 60m | bucket as system, 60; user as user, 40 | approved_public_buckets lookup, owner, ticket, static-site exception with expiry; no broad actor allowlist |
| Local account added to Administrators | BOTSV3-WIN-LOCAL-ADMIN-002 / High | */5 * * * *; -15m to -5m; 5m grace; Index Time | host + target_sid + create_time; throttle 60m | target_user as user, 50; dest host as system, 40 | approved provisioning identities and change windows; keep a separate alert for any unapproved admin-group addition |
| Suspicious PowerShell with external egress | BOTSV3-WIN-PS-EGRESS-003 / Medium; raise with privileged user, high-value endpoint, or destination reputation | */5 * * * *; -20m to -5m; 5m grace; Index Time | host + ProcessGuid; throttle 60m | user as user, 30; dest host as system, 40 | approved signer/hash, endpoint role, known management destinations, and internal CIDR inventory |

Configure separate ES Risk Analysis modifiers for the listed user and
system fields. The SPL returns the primary risk object/type/score and the
secondary CIM entity field. ES can attach additional risk modifiers to
other returned fields. [Risk object types and scores](https://help.splunk.com/en/splunk-enterprise-security-7/user-guide/7.3/risk-analysis/analyze-risk-in-splunk-enterprise-security).

## Rule-specific logic

1. S3 rule inspects normalized acl_grantee_uri with the suffix
   /(AllUsers|AuthenticatedUsers)$/ or a normalized public policy
   principal, excludes API errors, then looks up bucket in
   approved_public_buckets. It does not claim S3 object reads or
   exfiltration.
2. Windows rule maps Event 4720 TargetSid to Event 4732 MemberSid, keeps
   SubjectUserName as the actor, requires Administrators GroupSid
   S-1-5-32-544 or GroupName=Administrators, and requires a nonnegative
   interval no greater than 300 seconds.
3. Sysmon rule detects encoded command, FromBase64String,
   DownloadString, or IEX patterns in a PowerShell child process. After
   the indexed event/time filters, it orders the bounded result by host,
   ProcessGuid, and _time, carries the latest suspicious process event
   with streamstats, and accepts only a later Event 3 on the same process
   within 600 seconds. This avoids treating an earlier connection as
   post-execution egress. It excludes RFC1918 10/8, 172.16/12, and
   192.168/16. Production must also exclude organization-owned, VPN,
   cloud-private, link-local, and IPv6 ULA ranges.

The JSON fixture pairs are synthetic normalized examples, not raw
BOTSv3 records. They establish the intended logic only. Validate raw
extractions, lookup contents, CIM mappings, schedule, throttling,
late-data behavior, and false-positive rates in the intended Splunk ES
environment. Microsoft documents Event 1 and Event 3 ProcessGuid
correlation in [Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events).
