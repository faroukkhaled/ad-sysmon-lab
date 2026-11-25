# Writing rules

Rules use a subset of the Sigma format, so most simple Sigma rules can be dropped into `rules/`.

```yaml
title: Short, specific name
id: sl-0099            # unique, the loader rejects duplicates
status: experimental
description: What it finds and why it matters.
tags: [attack.persistence, attack.t1547.001]   # technique tags feed the coverage map
logsource: {product: windows, category: process_creation}
detection:
  img: {Image|endswith: '\reg.exe'}
  args: {CommandLine|contains|all: ['add', '\Run']}
  condition: img and args
level: medium
```

## Modifiers
`contains`, `startswith`, `endswith`, `all` (every value must match), `re`, `cidr`, `lt`, `lte`, `gt`, `gte`.
Matching is case-insensitive. A plain value may contain `*` and `?`. A value of `null` means the field is absent or empty.

## Conditions
`and`, `or`, `not`, parentheses, `1 of sel*`, `all of sel*`, `1 of them`, `all of them`.

## logsource
`category` maps to Sysmon event ids (`process_creation` = 1, `network_connection` = 3, `process_access` = 10,
`registry_event` = 12-14, `file_event` = 11, `dns_query` = 22, `wmi_event` = 19-21). `service: security`
restricts the rule to the Security log.

## Thresholds (extension)
```yaml
x-threshold: {group_by: [IpAddress], count: 5, window: 120}
```
Fires once per group when `count` matching events fall within `window` seconds.

## Testing a new rule
1. Add attack events for it to `sysmonlab/simulate.py`, labelled with the rule id.
2. Add a lookalike benign event so you also test for false positives.
3. Run `make evaluate`. It exits non-zero on a missed rule or a false positive. CI runs it too.
