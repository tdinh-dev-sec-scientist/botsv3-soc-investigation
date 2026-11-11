# BOTSv3 Conditional Incident Response Playbook

This playbook is for a hypothetical live Frothly incident; BOTSv3 is an
educational dataset. It is not a record of actions performed. It follows
NIST SP 800-61 Rev. 3, which integrates incident response into the NIST
CSF 2.0 risk-management functions. [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final).

## Govern and prepare

1. The incident commander opens an incident record and names the
   technical lead, cloud owner, endpoint/identity owners, legal/privacy
   contact, and communications lead.
2. Set scope: AWS account, bucket frothlywebcode, principal bstoll,
   web_admin, mkraeusen, FYODOR-L, ABUNGST-L, and the published period.
   Record that account compromise, public exposure, object access,
   exfiltration, and lateral movement remain unresolved.
3. Preserve immutable CloudTrail logs, Splunk raw events and search job
   IDs, endpoint telemetry, identity-provider and VPN records, and
   evidence hashes. Record time source, collection time, collector, and
   chain of custody.
4. Confirm business criticality and approved-public-bucket status before
   disruptive action. Record approval paths for credential suspension,
   bucket changes, endpoint isolation, and service recovery.

## AWS identity and S3

### Validate and preserve

1. Retrieve both raw PutBucketAcl and PutBucketPolicy CloudTrail events.
   Preserve eventID, requestParameters, response elements, principal/
   session ARN, source IP, user agent, MFA context, errorCode, and time.
2. Read the current bucket ACL and policy. Determine whether the ACL
   contains AllUsers or AuthenticatedUsers, whether a policy Principal is
   public, and whether S3 Block Public Access or account controls
   prevented effective exposure. Preserve state before changing it.
3. Query available S3 object data events, access logs, replication
   records, object versions, and egress. The portfolio currently has no
   evidence that objects were read or exfiltrated.

### Conditional containment for bstoll

If account compromise or unauthorized activity is substantiated:

1. Identify whether bstoll is an IAM user, IAM Identity Center user, or
   federated/assumed-role identity. Preserve key IDs, last-used data,
   active session identifiers, MFA/device context, and authorization
   state first.
2. For IAM user access keys, immediately set implicated keys to
   Inactive; rotate or remove them after evidence preservation and owner
   approval. Record key IDs before deletion.
3. Revoke active sessions using the correct identity path. For an
   assumed IAM role, use IAM's Revoke active sessions control/policy.
   For IAM Identity Center, end active sessions and remove assignments or
   apply the organization's deny policy as its runbook requires. For a
   direct IAM user, use the approved deny/credential containment process
   and disable console sign-in as appropriate. Do not assume a password
   reset invalidates every existing session.
4. Notify bstoll's manager/identity owner and review other identities
   using 107.77.212.175. Do not label the account compromised from the
   shared IP alone.

AWS documents separate session-revocation procedures for roles and IAM
Identity Center users. [Revoke IAM role sessions](https://docs.aws.amazon.com/us_en/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html),
[revoke Identity Center access](https://docs.aws.amazon.com/en_en/singlesignon/latest/userguide/revoke-user-permissions.html).

### Conditional bucket remediation and logging

1. If the bucket is unintentionally public, remove the public ACL grant
   or policy principal, enable appropriate account/bucket S3 Block Public
   Access settings, and verify effective access using an approved test.
   Re-test the application if the bucket has an approved public use.
2. Immediately enable CloudTrail S3 object-level data events for
   frothlywebcode, including GetObject and relevant write/delete events.
   Prefer a scoped selector for this bucket and response period. Preserve
   existing trail selectors first: switching to advanced selectors
   replaces basic selectors, and object data events can add cost.
3. Review GetObject, SelectObjectContent, PutObject, DeleteObject,
   replication, and access-log records for the exposure window. Report
   “no matching events found in available logs” or “logging unavailable”;
   missing logging is not proof of no access.

AWS says S3 data events record object-level activity and are not logged
by default; advanced selectors can scope logging by AWS::S3::Object and
resource ARN. [Enable S3 CloudTrail logging](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-cloudtrail-logging-for-s3.html),
[S3 data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-s3-data-events-governance.html),
[advanced selectors](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/filtering-data-events.html).

## Windows endpoints

1. If active callbacks are confirmed or the incident commander chooses
   precautionary containment, isolate FYODOR-L and ABUNGST-L with EDR
   network isolation. Preserve approved management/forensic access.
   ABUNGST-L has C2-like network records, but its compromise and
   relationship to FYODOR-L remain suspected.
2. Before killing PowerShell or removing files, acquire volatile memory
   if safe and authorized. Capture process tree, ProcessGuid, command
   lines, token/elevation state, loaded modules, network sockets, DNS
   cache, script/decode buffers, PowerShell history/logs, and registry
   state. Hash original and decoded artifacts; store them with chain of
   custody.
3. Preserve Sysmon Event IDs 1, 3, 11, 12-14 and Security events 4624,
   4688, 4720, 4732, and 7045 for both hosts. Pivot on source/target
   addresses, SubjectUserName/SID, MemberSid, process GUIDs, SMB
   sessions, WMI, remote service creation, and file transfer to establish
   or falsify movement.
4. Capture the svcvnc SID, creation event, group membership, logons, and
   dependent services/tasks. Then disable or remove the account and
   revoke credentials after confirming it is not a legitimate service.
5. Block 45.77.53.176 at approved DNS, proxy, and network controls after
   preserving traffic and validating it is not a shared service. Hunt
   the callback and suspicious file paths across endpoint inventory;
   collect SHA-256 before quarantine.

## Eradicate, recover, and improve

1. Rebuild FYODOR-L from a known-good image if memory/registry evidence
   confirms control tampering or system integrity cannot be established.
   Rebuild ABUNGST-L only if endpoint evidence supports compromise;
   otherwise maintain monitoring and preserve the rationale.
2. Rotate credentials for identities actually exposed to affected hosts,
   invalidate relevant tokens/sessions, review local administrator
   membership, and remove unauthorized persistence.
3. Reconnect each host only after endpoint telemetry is healthy,
   credential rotation is complete, persistence hunts are clean, and
   EDR/network monitoring is active. Monitor PowerShell execution, C2
   attempts, local-group changes, and cloud API anomalies.
4. Report impact as separate states: execution confirmed, account misuse
   suspected, public access unresolved, object access not observed in
   published evidence, and lateral movement unproven. Quantify affected
   data only from object-level and business-owner evidence.
5. Record root cause, evidence gaps, missed detections, owners, dates,
   and measurable improvements. Update bucket inventory, session
   revocation automation, endpoint isolation playbooks, ingestion-time
   alerting, and detection fixtures.

This maps preparation and oversight to CSF 2.0 Govern, Identify, and
Protect; operational handling to Detect and Respond; and restoration and
lessons to Recover and Improve.
