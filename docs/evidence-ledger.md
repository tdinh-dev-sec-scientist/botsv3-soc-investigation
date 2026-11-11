# BOTSv3 Evidence Ledger

## Scope and confidence rules

This ledger separates the event that is visible in published artifacts
from the actor's intent and any causal conclusion. Times below are the
UTC labels published by the original README. The repo reports a four-hour
UI/raw timestamp discrepancy; run the comparison in search-hygiene.md
before treating those labels as independently verified.

- [CONFIRMED] A specific event or behavior is shown in the cited telemetry.
- [SUSPECTED / HYPOTHESIS] A plausible interpretation has at least one material alternative.
- [NOT OBSERVED] The evidence is absent from the published artifact; this is not proof the full dataset lacks it.
- [BLOCKED] An attempted action has an explicit control outcome such as AccessDenied.

| Timestamp (UTC, as published) | Host / Entity | Observed Telemetry (Raw Fields) | Causal Link / Mechanism | ATT&CK ID | Calibrated Status | Falsifier / Next Pivot |
|---|---|---|---|---|---|---|
| 2018-08-20 09:16:12 | AWS, web_admin | CloudTrail eventName=CreateUser and CreateAccessKey; sourceIPAddress=35.153.154.221; errorCode=AccessDenied | API request was denied; no user or access key creation is established | T1136.003 Create Account: Cloud Account | [BLOCKED] | Confirm raw event errorCode and absence of subsequent successful creation; do not describe this as persistence achieved |
| 2018-08-20 09:35:27 | AWS, bstoll | CloudTrail ConsoleLogin; userIdentity.userName=bstoll; sourceIPAddress=157.97.121.132 | Login event is tied to the logged identity; identity compromise is not established | T1078 Valid Accounts | [CONFIRMED] login record; [SUSPECTED / HYPOTHESIS] adversary use | Inspect principal/session ARN, MFA, device, source history, user confirmation, and adjacent CloudTrail events |
| 2018-08-20 09:46:22 | Cisco ASA, mkraeusen | WebVPN session; username=mkraeusen; source IP reported as 107.77.212.175 | Same public IP later appears in bstoll activity; shared egress and credential/session reuse are both plausible | None assigned | [CONFIRMED] VPN record; [SUSPECTED / HYPOTHESIS] identity linkage | Check VPN session identifiers, NAT/VPN ownership, endpoint/device, and exact time overlap |
| 2018-08-20 10:01:41 | FYODOR-L | Sysmon EventCode=1; ParentImage=browser_broker.exe; Image=PowerShell; CommandLine contains encoded command; User=AzureAD\\FyodorMalteskesko | Browser-parent process creation is observed; a user click, download, email, or link is not shown by that process event | T1204 User Execution | [CONFIRMED] process execution; [SUSPECTED / HYPOTHESIS] user execution | Correlate browser download/history, file Zone.Identifier, email/web proxy, and user-interaction evidence; retain “first observed endpoint execution” absent that proof |
| 2018-08-20 10:07:06 and 11:32:12 | FYODOR-L | Sysmon EventCode=1; Image=fodhelper.exe; PowerShell parent reported | Process launch is visible; the ms-settings registry hijack and elevated token integrity are not published | T1548.002 Bypass User Account Control | [SUSPECTED / HYPOTHESIS] | Inspect Sysmon EventCode=12/13/14 or registry telemetry for HKCU\\Software\\Classes\\ms-settings and process token integrity/elevation |
| 2018-08-20 10:08:17 | FYODOR-L | Sysmon EventCode=1 CommandLine contains net.exe and svcvnc; Windows Security EventCode=4720 is reported by the DET-04 result | Local account creation is reported; retain actor and target from Subject* versus Target* fields | T1136.001 Create Account: Local Account | [CONFIRMED] account creation, subject to raw-event verification | Preserve raw 4720; map SubjectUserName/SubjectSid separately from TargetUserName/TargetSid |
| 2018-08-20 10:08:35 | FYODOR-L | Windows Security EventCode=4732; reported member svcvnc added to local Administrators | Account-to-group action is reported; require MemberSid/MemberName and Administrators GroupSid/GroupName in raw event | T1098.007 Additional Local or Domain Groups | [CONFIRMED] if raw target/member and group fields validate | Verify MemberSid equals 4720 TargetSid and GroupSid=S-1-5-32-544 or GroupName=Administrators; keep SubjectUserName as the modifier |
| 2018-08-20 10:11:00 and 11:32:12 | FYODOR-L | Sysmon EventCode=1 PowerShell process/command line; decoded script includes AMSI and ScriptBlock logging changes, RC4 decrypt, IEX, and URL callback | Behavior is supported by decoded command content; it is not a sample hash or definitive family/version identification | T1059.001, T1027, T1562.001, T1071.001 | [CONFIRMED] observed script behavior; [SUSPECTED / HYPOTHESIS] exact framework attribution | Preserve original encoded command and decoded bytes, calculate SHA-256 for any recovered payload, compare with a primary framework sample, and confirm network event by ProcessGuid |
| 2018-08-20 13:01:46 and 13:57:54 | AWS S3 bucket frothlywebcode; actor bstoll | CloudTrail eventName=PutBucketAcl; README reports bstoll from 107.77.212.175 | The API calls are established. Exact Grantee.URI / resulting ACL is not shown, so public exposure cannot be concluded | No exfiltration technique assigned | [CONFIRMED] ACL API calls; [SUSPECTED / HYPOTHESIS] public exposure | Inspect raw requestParameters.AccessControlPolicy.AccessControlList.Grant{}.Grantee.URI and current ACL/policy; preserve before/after state |
| During the ACL-change interval; no object times published | S3 bucket frothlywebcode | No S3 GetObject data-event result or server access log is included in the repo | No basis to claim an object was read, downloaded, or exfiltrated | None assigned | [NOT OBSERVED] object access/exfiltration in published evidence | Enable CloudTrail S3 object data events and review GetObject, SelectObjectContent, replication, access logs, object versions, and egress telemetry |
| 2018-08-20; exact start/end not published | FYODOR-L and ABUNGST-L | README reports 3,849 and 1,070 Sysmon EventCode=3 connections, respectively, to DestinationIp=45.77.53.176 and DestinationPort=443; DET-05 groups counts by host/IP/port | Shared callback destination supports a cross-host pivot and possible common targeting; it does not show how FYODOR-L reached ABUNGST-L | T1071.001 for observed web protocol; no lateral-movement ID claimed | [CONFIRMED] reported network records; [SUSPECTED / HYPOTHESIS] second-host compromise/movement | Bound first/last connection per host and ProcessGuid; inspect process creation, 4624 LogonType=3, 4688, remote WMI target, SMB/admin-share/RPC, named pipes, service creation/PsExec, and file transfer |
| Published artifacts do not show a host-to-host event | FYODOR-L → ABUNGST-L | No Event ID 4624 Type 3, remote WMI target, SMB/RPC pipe, PsExec/service-creation chain, or matching transfer event is presented in the public repo | No source-to-target mechanism is demonstrated | T1021.002 only if SMB/admin-share evidence is found | [NOT OBSERVED] in published telemetry | Search complete BOTSv3 sources for the fields above; absence from this repository's screenshots/snippets is not proof of absence from the dataset |

## Evidence-quality notes

- “Observed” means visible in the repo's report/query result claims; this audit cannot replay the private lab instance or validate result counts because the dataset archive and raw saved results are not committed.
- The PutBucketAcl row corrects a documentation typo: the README's reported source IP for bstoll is 107.77.212.175. Validate each value against the CloudTrail raw event before using it as evidence.
- The labels in the timestamp column are the original report's converted labels. The supplied SPL compares the original event epoch with raw XML and does not blindly add four hours.
- IOC enrichment is not included because no hashes or independently resolved network reputation evidence are published. Do not infer attribution from the decoded launcher pattern alone.

## Primary evidence references

- [BOTSv3 investigation README](https://github.com/tdinh-dev-sec-scientist/botsv3-soc-investigation/blob/main/README.md)
- [CloudTrail searches](https://github.com/tdinh-dev-sec-scientist/botsv3-soc-investigation/blob/main/queries/q-a1-a4-cloudtrail.spl)
- [Endpoint searches](https://github.com/tdinh-dev-sec-scientist/botsv3-soc-investigation/blob/main/queries/q-b1-b4-endpoint.spl)
- [DET-01 S3 ACL search](https://github.com/tdinh-dev-sec-scientist/botsv3-soc-investigation/blob/main/queries/det-01-s3-public-acl.spl)
- [DET-04 local admin search](https://github.com/tdinh-dev-sec-scientist/botsv3-soc-investigation/blob/main/queries/det-04-local-admin-account-creation.spl)
- [Microsoft Windows event 4720](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720), [event 4732](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732)
- [Sysmon event documentation](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
