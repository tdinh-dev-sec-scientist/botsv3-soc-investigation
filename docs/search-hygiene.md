# Search Hygiene and Telemetry Standardization

## Timezone discrepancy: compare epoch, do not add four hours by habit

Splunk stores _time as Unix epoch and renders it as human-readable time
in the UI. The display can be localized. This search parses raw Windows
SystemTime as UTC and compares its epoch directly with _time. Fractional
seconds are removed only for the comparison, so the expected absolute
delta is less than one second.

~~~spl
index=botsv3 sourcetype=XmlWinEventLog earliest=1534723200 latest=1534809600
  EventCode IN (1,3)
| fields _time host EventCode _raw
| rex field=_raw "SystemTime=\"(?<raw_systemtime>\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?Z)\""
| eval systemtime_whole_second=replace(raw_systemtime,"(\\.\\d+)?Z$","")
| eval raw_utc_epoch=strptime(systemtime_whole_second."+0000",
    "%Y-%m-%dT%H:%M:%S%z")
| eval epoch_delta_seconds=round(_time-raw_utc_epoch,3)
| fields _time raw_systemtime raw_utc_epoch epoch_delta_seconds host EventCode
~~~

Interpret the result:

- Delta near zero: _time already represents raw UTC event time; the
  four-hour difference was display formatting. Keep _time unchanged.
- Delta near plus or minus 14,400 seconds across representative events:
  inspect timestamp extraction and timezone configuration. Correct
  ingestion parsing only after validating raw event samples.
- Mixed deltas: investigate sourcetype-specific parsing, daylight-saving
  handling, and events without the same raw timestamp field.

Splunk documents that _time is stored as Unix time and human-readable
rendering occurs in Splunk Web; strptime parses a timestamp string into
Unix time. [Date and time functions](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.2/evaluation-functions/date-and-time-functions),
[date/time format variables](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.0/time-format-variables-and-modifiers/date-and-time-format-variables).

## Unix add-on contamination inventory and macro

First inventory the sourcetypes described in the original investigation.
The bounded range includes the 2018 incident day and the reported 2019
tail. Keep this inventory query unfiltered so it reveals collector host
and counts.

~~~spl
index=botsv3 earliest=1534723200 latest=1577836800
  sourcetype IN ("ps","top","lsof","netstat","PerfmonMk:Process")
| fields _time host sourcetype source
| stats count min(_time) as first_epoch max(_time) as last_epoch
    by host sourcetype source
| sort 0 host sourcetype source
~~~

The search macro excludes only those exact sourcetypes. It does not
exclude all Linux, Unix, or osquery telemetry. If inventory shows that a
listed sourcetype also contains legitimate BOTSv3 host data, add the
verified collector-host predicate before using the macro and reconcile
the resulting event counts.

Macro file: default/macros.conf

~~~ini
[botsv3_exclude_unix_ta_noise]
definition = NOT sourcetype IN ("ps","top","lsof","netstat","PerfmonMk:Process")
iseval = 0
description = Exclude exact Splunk-host Unix add-on sourcetypes reported as lab contamination; verify the host/sourcetype inventory before use
~~~

Apply the macro after the indexed time and source constraints in a
search. The exact invocation is included in queries/search-hygiene.spl.
This macro is a candidate based on the sourcetype families named by the
README. It cannot reproduce the reported 1.94M versus 2.84M counts
without the original Splunk instance, actual host values, app versions,
and raw data. Splunk documents reusable search macros in [Use search
macros](https://help.splunk.com/en/splunk-cloud-platform/manage-knowledge-objects/knowledge-management-manual/10.2.2510/search-macros/use-search-macros-in-searches)
and [macros.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.3/configuration-file-reference/9.3.13-configuration-file-reference/macros.conf).

## Time bounds, fields, and sort limits

The incident occurred on 2018-08-20. Use the bounded epoch range below
for retrospective timelines. Apply index, sourcetype, event identifiers,
and time bounds in the base search; project only needed columns with
streaming fields; then sort the reduced result. Apply the exclusion macro
as shown in queries/search-hygiene.spl.

~~~spl
index=botsv3 sourcetype=aws:cloudtrail earliest=1534723200 latest=1534809600
  eventName IN (PutBucketAcl,PutBucketPolicy,CreateUser,CreateAccessKey,
                AttachUserPolicy,StopLogging,DeleteTrail,ConsoleLogin)
| fields _time eventID userIdentity.userName sourceIPAddress eventName
    requestParameters.bucketName errorCode
| sort 0 _time
~~~

Splunk's default sort limit is 10,000 returned results. A long
sort _time can silently omit timeline rows. sort 0 _time removes the cap
but performs a full sort; use it only after selective index/sourcetype/
time/event filters. [Splunk sort command](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.4/search-commands/sort),
[write better searches](https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.2/optimize-searches/write-better-searches).

## Bounded process hunt without broad http wildcard

~~~spl
index=botsv3 sourcetype=XmlWinEventLog EventCode=1
  earliest=1534723200 latest=1534809600
| fields _time host User ParentImage Image CommandLine ProcessGuid
| where match(Image,"(?i)\\\\(powershell(?:_ise)?|pwsh|cmd)\\.exe$")
    OR match(CommandLine,
      "(?i)(?:^|\\s)-(?:enc|encodedcommand)(?:\\s|:)|downloadstring|frombase64string|(?:^|[;&|]\\s*)iex(?:\\s|\\(|$)")
| sort 0 _time
~~~

The pattern targets encoded PowerShell flags and download/decode tokens
instead of every command line containing http. Treat this as a hunt;
establish a baseline and threshold before scheduling it as a detection.
