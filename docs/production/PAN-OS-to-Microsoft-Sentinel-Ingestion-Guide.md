# PAN-OS to Microsoft Sentinel: Production Ingestion Guide

| Document control | Value |
| --- | --- |
| Version | 1.0 |
| Last reviewed | 21 October 2026 |
| Status | Implementation design and operational runbook; environment-specific approval pending |
| Audience | Network security, SIEM engineering, SOC, cloud platform, PKI and privacy teams |
| Scope | Production PAN-OS firewall telemetry ingestion, normalization, detection readiness and lifecycle management |
| Validation status | Documentation and query examples reviewed locally; no production deployment or tenant validation performed for this document |
| Accountable service owner | To be assigned |

> This is not a classroom lab or an instruction to modify an existing tenant. Resolve the decision register, validate configurations on the deployed versions, complete acceptance testing and obtain change approval before rollout. Commands and KQL below are reviewable examples, not evidence of a deployed solution. No tenant IDs, credentials, private keys or production IP addresses are embedded.

## Contents

1. [Architecture decision](#1-architecture-decision)
2. [Environment and approval register](#2-environment-and-approval-register)
3. [Collection scope](#3-collection-scope)
4. [Detection data contract](#4-detection-data-contract)
5. [CEF compatibility and field mapping](#5-cef-compatibility-and-field-mapping)
6. [Security, network and availability design](#6-security-network-and-availability-design)
7. [Implementation sequence](#7-implementation-sequence)
8. [Native CSV parsing and normalization](#8-native-csv-parsing-and-normalization)
9. [Analytics, Data Lake and summary rules](#9-analytics-data-lake-and-summary-rules)
10. [ATT&CK-oriented detection readiness](#10-attck-oriented-detection-readiness)
11. [Validation queries](#11-validation-queries)
12. [Acceptance tests and go-live gates](#12-acceptance-tests-and-go-live-gates)
13. [Monitoring and operational ownership](#13-monitoring-and-operational-ownership)
14. [Troubleshooting](#14-troubleshooting)
15. [Rollout, rollback and change control](#15-rollout-rollback-and-change-control)
16. [Handover package](#16-handover-package)
17. [References](#17-references)

## 1. Architecture decision

### 1.1 Recommended decision

For a new deployment on a current PAN-OS release, prefer the vendor's native syslog payload, subject to proving Sentinel parser and detection compatibility. Use encrypted transport, resilient collectors and a version-controlled normalization layer. Do not migrate a working production CEF integration until its replacement passes equivalent detection and operational tests.

Palo Alto no longer supports its CEF configuration guidance for releases after PAN-OS 10.0 and directs newer integrations toward standard syslog or another supported mechanism. This is a limitation of the vendor's guidance, not a statement that Microsoft cannot ingest CEF. [Palo Alto CEF support notice](https://docs.paloaltonetworks.com/resources/cef)

Choose one primary ingestion pattern per source/log family:

| Pattern | Payload and initial destination | Adoption condition |
| --- | --- | --- |
| A: Native syslog, preferred for evaluation | PAN-OS CSV within syslog; Syslog via AMA to `Syslog` | A tested version-aware parser, maintained normalization and compatible detections are available |
| B: CEF compatibility | Validated custom CEF within syslog; CEF via AMA to `CommonSecurityLog` | Required Sentinel content depends on CEF, and the organization accepts and owns the newer-PAN-OS compatibility risk |
| C: Engineered structured ingestion | Supported source feed and ingestion pipeline into approved custom or ASIM tables | Separate engineering design, security review, schema ownership and failure handling are approved |

Pattern C is not created by selecting a different table in the standard syslog connector. Its transformation/routing support must be verified for the selected source stream and destination schema.

### 1.2 Reference flow

```text
PAN-OS firewalls OR approved Panorama/log-collector forwarding point
  | private network; authenticated/encrypted syslog transport
  v
Resilient Linux syslog collectors
  | rsyslog/syslog-ng: TLS termination, bounded queues, monitoring
  | Azure Monitor Agent: associated DCR, managed machine identity
  v
Microsoft Sentinel-enabled Log Analytics workspace
  | native payload -> Syslog -> tested CSV parser/normalization
  | CEF payload   -> CommonSecurityLog -> validated field/ASIM mapping
  v
Analytics-tier security events -> detections, hunting, incidents
  |
  +-- approved long-term raw retention in Data Lake
  +-- optional bulk-only lake tables -> summaries -> custom Analytics tables
```

Microsoft documents the native-syslog and CEF destination distinction. Installing a collector does not automatically convert native PAN-OS CSV into structured `CommonSecurityLog` fields. [AMA syslog and CEF architecture](https://learn.microsoft.com/en-us/azure/sentinel/cef-syslog-ama-overview)

### 1.3 Compatibility gate

Microsoft's listed PAN-OS network/web ASIM parsers consume CEF. Do not assume they parse the native CSV route. Inventory the installed Content hub solution, parser version, rule dependencies and workbook expectations before choosing or changing format. [ASIM parser catalogue](https://learn.microsoft.com/en-us/azure/sentinel/normalization-parsers-list)

## 2. Environment and approval register

Complete this register before implementation. Example names are placeholders, not discovered resources.

| Decision/input | Required value or evidence | Approver |
| --- | --- | --- |
| Azure tenant, subscription, workspace resource ID and region | Approved production destination and data-residency assessment | Cloud owner |
| Firewall inventory | Serial, hostname, PAN-OS build, HA role, virtual systems, site and business owner | Network security |
| Forwarding point | Direct firewall, Panorama or log collector; avoid duplicate upstream paths | Network security |
| Format per log family | Native default CSV, frozen custom CSV or CEF; exact schema/profile revision | SIEM engineering |
| Management platform | Local PAN-OS, Panorama or Strata Cloud Manager; inheritance/override ownership | Network security |
| Collector platform | Supported Linux distribution, Azure VM or Azure Arc, sizing and patch policy | Platform owner |
| Availability | Failure domains, routing/failover behavior, RTO and acceptable event loss | Service owner |
| Network and PKI | Source routes/IPs, collector FQDNs, port, trust chain, certificate validation and renewal | Network/PKI |
| Volume | Average/peak EPS, average and maximum message size, burst duration and daily GB | SIEM engineering |
| Detection requirements | Required sources/fields, maximum acceptable delay, correlation horizon | SOC |
| Retention/tier | Per-table hot and total retention, legal hold/export requirements, lake onboarding | SOC/privacy/finance |
| RBAC | Deployment, operations, reader and incident-investigation access | Security owner |
| Change | Change ID, maintenance window, canary, rollback and sign-off | Change authority |

Assumptions requiring explicit confirmation: applicable licenses/security profiles are enabled; the network permits collector and Azure egress; the organization permits the proposed personal/security data processing. No prior lab settings or workspace names are assumed to apply.

## 3. Collection scope

This is a proposed production policy. Tune volume only after recording which detections a filter affects.

| Log family | Initial collection policy | Dependencies and cautions |
| --- | --- | --- |
| Traffic | Session-end events; deny/drop events; session-start for selected high-risk or long-lived sessions | Include internal lateral paths as well as perimeter traffic; end-only logging delays visibility on long sessions |
| Threat | All events in the agreed threat scope, including alert-only and blocked outcomes | Licensed/configured inspection profiles determine what exists; blocked does not mean compromised |
| URL Filtering | Security-relevant categories and the request context required by detections | Full benign URL history is a separate volume/privacy decision |
| WildFire submissions | Relevant verdicts and sample/report identifiers | Submission and verdict timing may differ; do not assume every file is submitted |
| Authentication | Failures and successes, reason, user and source context | Failures alone cannot establish successful account use |
| GlobalProtect | Authentication, connection/disconnection, status and endpoint/IP association | Include successful sessions and assigned private addresses for attribution |
| Configuration | Administrative changes, results and approved before/after detail | Do not sample; protect sensitive configuration content |
| System | Security/admin events, service/logging failures, clock/certificate problems, HA state | Do not remove informational events solely because their severity is low |
| User-ID | Mapping lifecycle and provenance when identity correlation uses it | Time-bounded mappings; reassigned IPs must not inherit historical users |
| HIP Match / Decryption / Data Filtering / Tunnel | When required by endpoint posture, TLS, DLP or tunneled-traffic use cases | Feature, visibility, privacy and licensing prerequisites must be recorded |

PAN-OS exposes multiple log families, including separate authentication and management-plane telemetry. Generate and forward each required type; a syslog server profile alone is insufficient. [PAN-OS field catalogue](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions), [Log Forwarding profiles](https://docs.paloaltonetworks.com/network-security/security-policy/administration/objects/log-forwarding)

Do not globally filter on severity or action. Informational allowed connections, successful logins and successful configuration changes can be essential evidence. An Azure NSG drop before the firewall is not a PAN-OS deny event. A client timeout alone is not proof of a firewall policy action.

## 4. Detection data contract

### 4.1 Core attributes

The names below describe required semantics, not a promise of identically named `CommonSecurityLog` columns. Evaluate completeness by log family and applicability.

| Domain | Attributes to preserve | Contract rule |
| --- | --- | --- |
| Provenance | Device serial/name, PAN-OS build, log type/subtype, virtual system, site, collector, parser revision | Distinguish reporting firewall from relay/collector; inventory provides fields not emitted in each event |
| Time | Device generated/receive time, session start, high-resolution time where available, timezone, Azure ingestion time | Retain source timestamps and processing timestamps separately; normalize to UTC without discarding originals |
| Connection | Original source/destination IP and port, protocol, App-ID | Retain IPv6; application identity is not the transport protocol |
| NAT | Translated addresses and ports for both sides | Required when NAT occurs; record absent/not-applicable distinctly from parse failure |
| Policy/topology | Action, action source, rule name/UUID, zones, interfaces | Retain the original action as well as normalized disposition |
| Session | Session ID, sequence number, start/duration/end reason, repeat count | Preserve numeric range; session ID is not globally unique |
| Volume | Client-to-server/server-to-client bytes and packets | Establish direction using network context before calling a transfer Internet egress |

These network attributes and their semantics are described in [PAN-OS Traffic Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields).

### 4.2 Security and identity attributes

For Threat/URL/WildFire, retain signature ID/name, category/subtype, severity, direction, enforcement outcome, content version, URL/domain, file hash/type, report/packet-capture references, and relevant HTTP metadata. Populate only when emitted and authorized; encrypted traffic does not automatically expose full URLs or payloads. A URL may contain a password-reset token or other secret, so collection and display policies must be reviewed. [PAN-OS Threat Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields)

For Authentication/GlobalProtect, preserve user identity, source public address, assigned private address, device/host identity, gateway/portal, authentication method/stage, result/reason and session timing. Preserve the distinction between authentication success and a successfully established VPN connection. [Authentication fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/authentication-log-fields), [GlobalProtect fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/globalprotect-log-fields)

For Configuration, preserve administrator, administrative source host, client/channel, command, result, affected path, before/after detail where approved, sequence and commit context. A change request or command is not necessarily an effective committed change; verify the result and resulting configuration. [PAN-OS Config Log Fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/config-log-fields)

### 4.3 Event identity and counting

Define two separate keys in the normalization design:

- **Event key:** reporting device serial + log family + source sequence + event timestamp, with virtual system and reboot/sequence-reset handling where necessary. Preserve sequence as a string or validated 64-bit value. Test collisions across restarts and HA devices; retain an evidence hash when useful.
- **Session correlation key:** device + virtual system + session ID + session start/time window, augmented by original connection tuple. Different log families may reference one session without being duplicates.

Do not deduplicate on session ID alone. Do not add start and end byte counters as independent transfers. Preserve repeat count separately from row count and distinct sessions; its meaning varies by source/log type. Exactly-once delivery is not assumed.

Maintain `ParseStatus`, parser/profile version, field applicability and error counters. Missing values must remain visible; do not replace an unknown source user, action, signature or timestamp with a fabricated value.

## 5. CEF compatibility and field mapping

Apply this section only to Pattern B or a separately approved native-to-CEF conversion. CEF header identity, escaping and log-type-specific extension semantics are part of the contract.

| PAN-OS meaning | CEF key | `CommonSecurityLog` field |
| --- | --- | --- |
| Original endpoints | `src`, `dst` | `SourceIP`, `DestinationIP` |
| Original ports | `spt`, `dpt` | `SourcePort`, `DestinationPort` |
| Transport / App-ID | `proto`, `app` | `Protocol`, `ApplicationProtocol` |
| Original action | `act` | `DeviceAction` |
| User names | `suser`, `duser` | `SourceUserName`, `DestinationUserName` |
| Device serial | `deviceExternalId` | `DeviceExternalID` |
| Reporting device name | `dvchost` | `DeviceName` |
| Translated addresses | `sourceTranslatedAddress`, `destinationTranslatedAddress` | `SourceTranslatedAddress`, `DestinationTranslatedAddress` |
| Translated ports | `sourceTranslatedPort`, `destinationTranslatedPort` | `SourceTranslatedPort`, `DestinationTranslatedPort` |
| Directional bytes | `out`, `in` | `SentBytes`, `ReceivedBytes` |
| URL / file digest | `request`, `fileHash` | `RequestURL`, `FileHash` |
| Receive / start time | `rt`, `start` | `ReceiptTime`, `StartTime` |

Validate these mappings against observed events. [Microsoft CEF mapping](https://learn.microsoft.com/en-us/azure/sentinel/cef-name-mapping)

The current table schema identifies legacy numeric custom fields and `ExternalID` as being replaced by `FieldDeviceCustomNumber*` and `ExtID`. Inspect actual field population and range before building keys. PAN-specific extensions may require explicit parsing from `AdditionalExtensions`; they are not automatically first-class columns. [CommonSecurityLog schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/commonsecuritylog)

Implementation requirements:

- Keep a per-log-type mapping manifest, including custom-field labels and header event class/name semantics. Do not assume `cn1` always means session ID or `cs1` always means a rule.
- Escape CEF delimiters, backslashes and equals signs appropriately. Test quotes, non-ASCII usernames, long URLs and configuration details against the actual receiver.
- Keep templates in source control as single-line payload definitions. Do not paste PDF-wrapped templates into production.
- Validate sender, daemon and agent message-size limits using representative maximum-size events. Receiving a record does not prove that its tail was not truncated.
- Do not add classroom marker fields, sample identities or synthetic vendor names to live device templates.
- If a compatibility conversion is introduced, retain provenance and a controlled raw-evidence route; avoid silently rewriting vendor semantics.

Use Microsoft's [CEF troubleshooting reference](https://learn.microsoft.com/en-us/azure/sentinel/cef-syslog-ama-troubleshooting) to check header structure, escaping and unmapped fields. Test with actual PAN-OS output, not only synthetic messages.

## 6. Security, network and availability design

### 6.1 Transport boundaries

| Boundary | Production requirement |
| --- | --- |
| Firewall/forwarding point to collector | Private routed path; SSL/TLS listener with approved trust and certificate validation; TCP 6514 is an example, not a required fixed port |
| Collector syslog daemon to AMA | Local host delivery configured by the supported connector setup; never expose an internal AMA port to device networks |
| AMA to Azure | Outbound HTTPS to the documented cloud/region endpoints, or approved Azure Monitor Private Link design |
| Administration | Restricted management plane, MFA/PIM where applicable, audited changes and no public unrestricted SSH |

Palo Alto's current syslog guidance specifies TLS 1.2 for SSL syslog and describes client-certificate setup when the receiver requires client authentication. Validate server trust and identity checks for the deployed PAN-OS build; do not infer mutual authentication merely from selecting SSL. Configure collector policy accordingly and test expired/untrusted certificates and revocation access. [PAN-OS syslog TLS configuration](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/configure-syslog-monitoring)

Maintain a certificate register with owner, issuing CA, permitted identities, expiry, renewal lead time, revocation dependencies and rotation procedure. Restrict collector ingress to authorized source networks/identities. Permit only a reviewed exception for unencrypted TCP; UDP is not the baseline for a loss-sensitive production feed.

For Azure egress, follow the current AMA endpoint list and do not apply HTTPS inspection to required AMA service connections. In an AMPLS design, validate DCE association and private DNS before removing public egress. Private connectivity to a collector alone does not establish private AMA ingestion. [AMA networking](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-network-configuration), [DCE requirements](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-endpoint-overview)

### 6.2 Resilience and capacity

The following are design requirements, not claims of built-in end-to-end delivery guarantees:

- Place collector capacity across independent failure domains and test the chosen load-balancing or failover mechanism.
- Establish whether multiple PAN-OS destinations replicate events or provide the intended failover. Two configured destinations do not automatically mean load balancing.
- Choose direct firewall OR upstream collector forwarding for a given primary stream; accidental dual forwarding creates duplicates.
- Configure bounded disk-assisted queues and persistence appropriate to the daemon. Monitor queue age, queue capacity, drops, disk I/O, disk exhaustion and post-outage replay.
- Size for peak EPS and maximum event length, including a collector failure and backlog drain. Do not size using daily average EPS alone.
- Review PAN-OS forwarding buffers, daemon buffering and AMA buffering separately. Test each boundary; transport ACK does not prove workspace ingestion.

Planning estimate: `queue bytes = peak EPS x measured bytes/event x tolerated outage seconds x safety factor`. Include storage overhead, rotation, encryption and replay margin. Measure sustained replay throughput above normal load; otherwise the backlog never drains. Load-test the exact OS, agent, TLS and disk configuration rather than quoting an unverified universal events-per-second limit.

### 6.3 Access and data protection

Use least-privilege roles scoped to deployment/operations tasks; do not grant subscription Owner to collectors or SOC readers. Use the supported machine identity for AMA and manage Arc permissions separately where required. Separate the people who can change DCRs/retention from routine log readers.

Limit raw configuration, URL, user and device data to approved investigators. Redact secrets before collection where feasible without destroying approved detection keys; query-time masking alone does not remove stored secrets. Protect relay spool files, local archives, exports and backups with access control, encryption and retention. Assess data residency, legal hold and evidence integrity separately from a table-retention setting.

## 7. Implementation sequence

### Step 1: Baseline and approve

Export the current firewall forwarding/profile settings and relevant DCR/collector configuration. Record existing destinations and expected EPS per device/log type. Agree on canary sources, approved test accounts/assets, change window and rollback. Do not interrupt the existing security feed to discover how the new one behaves.

### Step 2: Prepare the Sentinel destination and collectors

Verify the production workspace, applicable Sentinel solutions, supported Linux OS, machine identity, and Azure Arc prerequisites for non-Azure collectors. Install AMA using the supported connector workflow and associate each intended collector with the correct DCR. Use current deployment instructions, not a legacy agent/shared-key setup. [Microsoft deployment prerequisites and workflow](https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-syslog-ama)

Configure the daemon's secure listener, certificate/key permissions, source restrictions, message-size policy, framing, queue limits and monitoring. Preserve the syslog header/body boundary and device identity. Run a configuration validation before a controlled reload; inspect the connector-generated daemon configuration before adding rules to avoid duplicate delivery.

Diagnostic examples for an approved rsyslog/Linux collector; service names vary by distribution:

```bash
# Read-only checks; these do not configure TLS, queues or forwarding.
sudo rsyslogd -N1
systemctl is-active rsyslog
systemctl is-active azuremonitoragent
sudo ss -lntp
df -h
timedatectl status
```

No generic TLS listener configuration is supplied: certificate identity policy, daemon packages, file layout and forwarding integration must match the approved platform. Keep the deployable listener configuration and tested rollback in the handover package.

### Step 3: Configure the DCR collection boundary

Select Syslog via AMA for native CSV or CEF via AMA for CEF. Select the approved collectors, facilities and severities, and verify the destination workspace. Recommended organizational conventions are a dedicated facility for native PAN-OS and a different dedicated facility for CEF if both exist; the actual values must be approved and consistent end to end.

During canary validation, include all severity levels needed by the source profile. Confirm that low-severity traffic/configuration/authentication events survive the DCR. Check for overlapping DCRs on each collector. Scope filtering to reviewed sources; a shared `Syslog` table may also contain Linux authentication and other network devices.

Do not change all of `Syslog` or `CommonSecurityLog` to a new tier to optimize one firewall feed. Do not assume the standard stream can write to an arbitrary custom table without a supported routing/transformation design.

The current `Syslog` schema lists lake support but no Basic-plan support. Do not equate a native-syslog route with availability of the Basic plan. [Syslog table capabilities](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/syslog)

### Step 4: Configure the PAN-OS server profile

For locally managed PAN-OS, the starting path is **Device > Server Profiles > Syslog**. Use the equivalent controlled template/device-group workflow for centrally managed devices.

1. Enter the approved collector destination, matching transport/port, syslog header format and facility.
2. For Pattern A, retain the version-documented default native payload unless there is a justified, frozen custom schema. BSD/IETF is the outer header choice, not CSV versus CEF.
3. For Pattern B, install only reviewed log-type-specific CEF templates and preserve the mapping manifest.
4. Configure required trust/client certificates, source/service route and reachability. Record the actual source interface/address.

Use [Palo Alto's current syslog procedure](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/configure-syslog-monitoring) for version-specific UI and certificate behavior.

### Step 5: Attach forwarding and enable event generation

Create match lists for required policy-related log types in **Objects > Log Forwarding**, then attach the appropriate profile to the relevant policy rules. Configure management-plane log forwarding through **Device > Log Settings** or the equivalent centralized controls for the deployed version. Verify Authentication and GlobalProtect individually rather than assuming a Traffic profile covers them. [Forwarding profile scope](https://docs.paloaltonetworks.com/network-security/security-policy/administration/objects/log-forwarding)

Use session-end logging as the traffic accounting baseline. Add session-start or another supported visibility mechanism where waiting for a long-lived session to close violates the detection objective. Ensure security profiles actually generate required threat/URL/file events. Confirm deny/default-rule logging and internal paths explicitly; do not assume only named allow rules matter.

### Step 6: Commit and verify a canary

Commit/push using normal change control. Inspect local PAN-OS events first, then collector reception, workspace raw rows, normalized fields and rule results. Record a known event's device time, receive time and ingestion time. Validate content as well as arrival counts. Observe representative business cycles, burst load and controlled collector failover before expanding scope.

### Step 7: Deploy parsers and detections, then optimize

Run the normalization tests in section 8, acceptance tests in section 12 and rule-equivalence tests for existing CEF content. Obtain SOC sign-off before enabling paging or automatic response. Only after baseline volume and detection dependencies are known should filters, raw retention or lake-only routes be changed.

## 8. Native CSV parsing and normalization

### 8.1 Parser ownership

The native route requires an implementation, not just a connector. Approve one of:

- A verified installed parser that explicitly supports this payload/version.
- A maintained query-time parser over `Syslog`, with bounded filters and performance tests.
- An approved structured-ingestion pipeline with controlled schemas and a dead-letter/error path.

A query-time parser creates a query result, not a new physical table. A summary rule cannot be assumed to call an arbitrary workspace function; materialization and function support need separate verification.

Organize normalized output by event semantics: Network Session, Authentication, Web Session, Audit and security-alert context as appropriate. A Traffic event is not an authentication event, and a Config command must not be normalized as a network permit. Use ASIM where its schema fits; preserve PAN-specific fields separately. [ASIM usage](https://learn.microsoft.com/en-us/azure/sentinel/normalization-about-parsers), [Network Session schema](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-network)

### 8.2 CSV safety and schema drift

- Treat the outer syslog header and CSV payload as separate layers. Validate the exact body arriving in `SyslogMessage` before applying offsets.
- Use a CSV-aware parser; `split(message, ',')` breaks quoted commas and can silently shift security fields.
- Preserve empty/reserved positions. Default native format and a shortened custom format do not share an interchangeable positional schema.
- Maintain a manifest per PAN-OS build range/log type/profile revision. Validate new appended fields and rejected layouts during upgrades.
- Reject or quarantine malformed/truncated/unknown layouts into a monitored path. Preserve controlled raw evidence; never silently discard them.
- Do not coerce a malformed action to allow, a parse error to zero bytes, or a missing authentication status to success.

Kusto's `parse_csv()` understands a single CSV record, including quoted delimiters; it does not parse multiple independent records in one row. This does not by itself validate a PAN-OS schema. [Kusto CSV parsing](https://learn.microsoft.com/en-us/kusto/query/parse-csv-function)

Diagnostic only, after confirming the unmodified default payload starts in `SyslogMessage`. The indices below are not a complete production parser:

```kusto
Syslog
| where TimeGenerated > ago(1h)
| where Facility =~ "local5" // EXAMPLE: replace with the approved native facility
| extend Fields = parse_csv(SyslogMessage)
| extend CandidateType = toupper(tostring(Fields[3])),
         CandidateSerial = tostring(Fields[2]),
         FieldCount = array_length(Fields)
| where CandidateType in ("TRAFFIC", "THREAT", "CONFIG", "SYSTEM", "GLOBALPROTECT", "AUTH", "USERID")
| summarize Rows=count(), MinFields=min(FieldCount), MaxFields=max(FieldCount)
    by CandidateSerial, CandidateType
```

Use an approved device inventory and parser error feed to find sources excluded by this discovery filter; no output does not establish source health. Prefixes, a custom schema or an unrecognized log type invalidate this example's assumptions.

### 8.3 Parser acceptance corpus

Retain sanitized fixtures for every required log type/subtype, IPv4/IPv6, NAT/no NAT, absent users, quoted commas/quotes/backslashes, non-ASCII text, maximum-length values, duplicate events, sequence reset, HA transition, daylight-saving/timezone boundaries and malformed/truncated records. Include each deployed PAN-OS/profile revision.

For each fixture, assert expected field values, types, time conversion, original outcome, correlation keys and error behavior. Review schema changes before PAN-OS upgrades. Store raw fixture, expected output, parser revision and test result together.

## 9. Analytics, Data Lake and summary rules

### 9.1 Placement policy

Keep the raw events required for timely detections and multi-table investigations in Analytics. Consider lake-only placement for high-volume lower-urgency data only after dependency, latency and cost tests. Long-term lake retention of Analytics data is different from moving a table entirely to lake-only. Tier changes operate at table level and can disable existing real-time analytics/hunting dependencies. [Sentinel tier behavior](https://learn.microsoft.com/en-us/azure/sentinel/manage-data-overview)

| Dataset | Proposed starting placement | Approval condition |
| --- | --- | --- |
| Threat, authentication, VPN, configuration, important system events | Analytics | Minimum detection and investigation horizon signed off |
| Traffic supporting timely scanning/C2/lateral-movement rules | Analytics | Keep the relevant raw timing and connection detail |
| Routine high-volume allowed traffic | Evaluate a separate lake-only dataset | Prove no urgent rule dependency and accept delayed summaries |
| Historical raw evidence | Approved total retention/lake policy | Residency, retrieval, legal hold and cost reviewed |
| Summarized features | Custom Analytics tables | Output schema, latency, source drilldown and rule behavior tested |

The table layout must precede row-level hot/cold routing. Neither a mixed `CommonSecurityLog` table nor a shared `Syslog` table can assign a different tier to each row. Separating datasets requires a supported and tested pipeline; avoid paying for the same raw event in multiple full-volume tables without a documented benefit.

### 9.2 Summary-rule constraints

Current documented `binSize` values begin at 20 minutes. Add configured arrival delay, processing and downstream detection scheduling to the latency budget. Summary output is a custom Analytics table, not an alert. Avoid a hardcoded relative time filter in the rule body; the engine defines the processing window. Preserve source first/last times independently of the summary row's generated time. [Summary-rule properties](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/summary-rules#summary-rule-properties)

Lake-sourced summary queries have source/operator restrictions; do not assume arbitrary multi-lake-table joins or user-defined parser functions are available. Use the supported lake job mechanism for broader historical analysis, or correlate promoted summaries with hot events in Analytics. [Tier comparison](https://learn.microsoft.com/en-us/azure/sentinel/manage-data-overview#compare-the-analytics-and-data-lake-tiers), [KQL/summary/search job comparison](https://learn.microsoft.com/en-us/azure/sentinel/datalake/kql-jobs-summary-rules-search-jobs)

### 9.3 Illustrative summary contract

The following table and fields are **proposed custom schema**, not built-in columns and not provisioned by this document. Only use this example after a structured-ingestion pipeline creates and validates `PANOSTraffic_CL`:

| Field | Type | Required semantics |
| --- | --- | --- |
| `TimeGenerated` | datetime | Approved source event timestamp used for processing |
| `DeviceSerial`, `VirtualSystem` | string | Original reporting firewall/virtual system |
| `SourceEventKey` | string | Non-empty, tested event key for exact duplicates |
| `SourceIP`, `DestinationIP` | string | Original addresses |
| `SourceUser`, `SourceZone`, `DestinationZone` | string | Original identity and network boundaries; null/empty allowed when not applicable |
| `Application`, `DeviceAction` | string | Application identity and original disposition |
| `EventPhase` | string | Explicit start/end/deny/drop classification |
| `SentBytes`, `ReceivedBytes` | long | Non-negative client-to-server/server-to-client counts |
| `ParseStatus` | string | Explicit parser outcome, for example `Success` |

Example rule query body: end-record volume accounting only, not a scan detector or full session census. Configure `binSize=20` and an approved `binDelay` outside this body. No function dependency is introduced.

```kusto
PANOSTraffic_CL
| where ParseStatus == "Success" and EventPhase == "end"
| where isnotempty(SourceEventKey)
| summarize arg_max(TimeGenerated, *) by SourceEventKey
| summarize SourceFirstSeen=min(TimeGenerated), SourceLastSeen=max(TimeGenerated),
            EndRecordCount=count(),
            TotalSentBytes=sum(SentBytes), TotalReceivedBytes=sum(ReceivedBytes)
    by DeviceSerial, VirtualSystem, SourceIP, DestinationIP,
       SourceUser, SourceZone, DestinationZone, Application, DeviceAction,
       SourceWindowStart=bin(TimeGenerated, 20m)
```

Suggested destination: `PANOSTrafficSummary_CL`. `EndRecordCount` deliberately does not claim to equal distinct sessions when the source aggregates repeats. The event-key grouping only handles duplicates inside the processed bin; validate delayed replays and cross-bin duplicates separately. Missing keys, parser errors and missing counters need separate health checks. This example is not tenant-executed or production-approved.

Do not infer beacon timing from a coarse aggregate, discard all port information before a port-scan use case, or add distinct counts across windows. Lists can truncate, approximate counts have error, and high-cardinality grouping can eliminate the cost benefit. Retain raw drilldown. Monitor failed/skipped bins and late events.

### 9.4 Cost decision

Model measured source volume, peak compute/collector requirements, raw ingestion/storage, lake processing, summary-result ingestion/storage, exports and monitoring. Summary-rule processing is not a promise of zero total cost; source-plan scanning and output ingestion can be billable. [Summary pricing](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/summary-rules#summary-rule-pricing-model)

Have finance approve retention using current region/contract pricing. No default retention period or fixed savings percentage is assumed in this guide. Reassess after format expansion, inspection enablement or a PAN-OS upgrade.

## 10. ATT&CK-oriented detection readiness

These are proposed detection hypotheses, not deployed analytics rules or claims of full technique coverage. ATT&CK IDs reflect references checked on the document review date; recheck mappings when content changes.

| Hypothesis | ATT&CK mapping | Required PAN evidence | Corroboration and limits |
| --- | --- | --- | --- |
| One internal source probes many services/hosts | [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | Original endpoints/ports, action, precise times, zones, repeat semantics | Compare authorized scanners; endpoint process/network telemetry improves attribution |
| Repeated authentication failures against an account | [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | Authentication outcomes, user, source, method, time | Reconnect loops/stale credentials are benign alternatives; PAN Traffic alone is insufficient |
| Failures spread across many accounts | [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) | Multi-user authentication patterns, source and outcomes | Describe as possible spray; logs usually do not expose which passwords were attempted; enrich with `SigninLogs` where identities align |
| Attempted exploitation of an exposed application | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | Relevant signature, destination exposure/NAT, URL/context and enforcement | A blocked signature match does not establish compromise; use application and endpoint evidence |
| Suspicious repeated web communications | [T1071.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001/) | App-ID, destinations, timing, URL/SNI when visible, threat context | Port 443 is not C2; use DNS, threat intelligence and endpoint process attribution |
| Unusual transfer over a supported C2 channel | [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) | Directional bytes, destination, application and session context | Volume alone is insufficient; establish C2 and correlate file staging/process activity |
| A firewall rule is weakened and new traffic follows | [T1686.002 Network Device Firewall](https://attack.mitre.org/techniques/T1686/002/) | Admin/source, change detail/result, commit context, rule UUID and subsequent traffic | Exclude approved changes; correlate identity and management activity; do not label every commit malicious |

Cross-table linkage must include identity normalization, a bounded event-time window, reliable host/IP mappings and network scope. `SecurityEvent`, Linux authentication in `Syslog`, `SigninLogs`, `AuditLogs`, endpoint telemetry and `AzureActivity` are separate feeds that must each be onboarded and verified. A log table existing is not proof that required events are arriving.

`AzureActivity` can show Azure control-plane network changes, such as NSG/routing operations; it does not replace PAN-OS configuration telemetry or show firewall session payloads. A public NAT address shared by many hosts is not a reliable standalone join key.

For every production analytics rule, record source/table/parser versions, required-field completeness, event-time semantics, lookback/frequency, tested positive and negative cases, entity mapping, incident grouping, suppression exceptions and response owner. Test controlled failures/known benign actions under approval; never generate credential attacks or exploit traffic against production assets merely to validate ingestion.

## 11. Validation queries

Run in the approved workspace. Inspect schemas first. These are diagnostic examples and require adaptation to the selected format; none was executed against a production tenant for this guide. Limit raw-data visibility and avoid exporting sensitive payloads into tickets.

### 11.1 Collector-side raw arrival, native route

```kusto
Syslog
| where TimeGenerated > ago(1h)
| where Facility =~ "local5" // EXAMPLE facility only
| summarize Rows=count(), LastSeen=max(TimeGenerated),
            ApproxBilledGiB=sum(_BilledSize)/1024.0/1024.0/1024.0
    by Computer, HostName, Facility, SeverityLevel
| order by LastSeen desc
```

This checks the raw collection boundary, not successful PAN parsing. `Computer`/`HostName` must be interpreted against actual relay behavior; do not substitute collector identity for firewall serial. `_BilledSize` is a volume estimate, not an invoice calculation. Compare to the independent expected-device inventory so missing devices do not disappear from the report.

### 11.2 CEF arrival and processing latency

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor == "Palo Alto Networks" and DeviceProduct == "PAN-OS"
| extend ProcessingDelaySeconds = datetime_diff('second', ingestion_time(), TimeGenerated)
| summarize Rows=count(), LastSeen=max(TimeGenerated),
            P95ProcessingDelaySeconds=percentile(ProcessingDelaySeconds, 95),
            NegativeDelayRows=countif(ProcessingDelaySeconds < 0)
    by DeviceExternalID, DeviceName, Activity, DeviceEventClassID
```

This is ingestion-minus-`TimeGenerated`, not automatically end-to-end device latency. Verify how the deployed pipeline assigns `TimeGenerated`, and measure source generation-to-receipt separately. An empty result needs a missing-feed alert, not a healthy status. Header vendor/product values must match the approved live profile.

### 11.3 CEF traffic required-field check

The traffic selector below assumes the approved profile places `TRAFFIC` in the header name/`Activity`. Adapt it if the deployed profile uses another event name.

```kusto
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Palo Alto Networks" and DeviceProduct == "PAN-OS"
| where Activity =~ "TRAFFIC"
| summarize Rows=count(), MissingSerial=countif(isempty(DeviceExternalID)),
            MissingSource=countif(isempty(SourceIP)),
            MissingDestination=countif(isempty(DestinationIP)),
            MissingAction=countif(isempty(DeviceAction)),
            MissingApplication=countif(isempty(ApplicationProtocol))
| extend MissingSourcePct=iff(Rows == 0, real(null), 100.0*MissingSource/Rows)
```

Zero rows is a failed or not-yet-established validation, not zero missing fields. Add conditional checks for NAT, users, signatures and zones only where applicable. For a truly unknown application, distinguish PAN's original classification from an empty field caused by parsing.

### 11.4 CEF numeric ID and custom-field inspection

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor == "Palo Alto Networks" and DeviceProduct == "PAN-OS"
| project TimeGenerated, Activity, DeviceEventClassID, DeviceExternalID,
          ExtID=tostring(column_ifexists("ExtID", "")),
          LegacyExternalID=column_ifexists("ExternalID", int(null)),
          Numeric1=column_ifexists("FieldDeviceCustomNumber1", long(null)),
          LegacyNumeric1=column_ifexists("DeviceCustomNumber1", int(null)),
          DeviceCustomNumber1Label,
          DeviceCustomString1Label, DeviceCustomString1,
          DeviceCustomString4Label, DeviceCustomString4,
          DeviceCustomString5Label, DeviceCustomString5
| take 20
```

Verify against known source records. An absent legacy field does not prove data loss if the replacement is populated, and a populated numeric slot does not prove it contains a session ID. Keep display/export permissions appropriate for identifiers and configuration details.

## 12. Acceptance tests and go-live gates

All thresholds below are proposed starting criteria, not vendor service guarantees. Replace them with approved values in the change record. An unmet mandatory gate blocks cutover.

| Test | Evidence to record | Proposed pass condition |
| --- | --- | --- |
| Identity/destination | Source and collector inventory, workspace resource ID | Every expected device/log family reaches only approved destinations |
| TLS positive/negative tests | Certificate chain, identity/trust tests, expiry/renewal test | Valid peers accepted; invalid/untrusted peers rejected under approved policy |
| Field correctness | Raw source record and normalized comparison | All applicable mandatory attributes correct in the acceptance corpus; no silent truncation |
| Parser errors | Valid and malformed fixtures | Valid fixtures pass; malformed/unknown layouts surface as errors, not plausible fabricated events |
| Timestamp accuracy | Device, collector and workspace timestamps | UTC conversion correct; example skew target <=60 seconds, explicitly approved |
| Detection latency | Source-event to rule/incident timings | Meets each use case's signed SLO; account for session-end reporting and summary delay |
| Completeness | Matched test events plus per-device/family counters | No unexplained loss in controlled canary; broader volume deviation investigated |
| Duplicate control | Event-key comparisons, multiple-path/failover tests | No unexplained duplicates or inflated session/byte accounting |
| Failure/recovery | Collector loss, agent egress interruption, bounded backlog/replay | Meets approved loss/RTO limits; queues drain and alerts fire |
| Missing-feed monitoring | Disable only an approved test feed temporarily | Independent inventory detects the missing source/family and pages the owner |
| Detection equivalence | Positive/negative scenarios for affected rules/workbooks | Expected outcomes, entities and raw drilldown retained after format/tier changes |
| Access/privacy | Reader/admin tests, sample URL/config handling | Least privilege and approved data handling verified |
| Budget | Measured normal/peak daily volume and forecast | Finance/service owner approves steady-state and burst cost |
| Rollback | Restore rehearsal and expected feed verification | Previous working path recoverable without deleting evidence |

For naturally quiet Configuration/System streams, agree on a safe periodic canary or a separate forwarding-health signal. A collector heartbeat does not prove every device and log family is healthy. Do not perform disruptive changes, authentication lockouts or malicious-content tests without dedicated authorization.

## 13. Monitoring and operational ownership

| Control | Suggested owner | Signal/action |
| --- | --- | --- |
| Source liveness | SIEM operations + network team | Expected inventory joined to latest event by device/log family; investigate silence and sudden source-count changes |
| Parser/schema health | SIEM engineering | Error rate, unexpected layouts, required-field null rates and signature/action drift; block unreviewed upgrades |
| Collector capacity | Platform operations | CPU/memory, disk/queue use, queue age, drops, TLS handshake failures and replay rate |
| Agent/DCR health | Cloud monitoring | Agent availability, association/config drift, egress failures and overlapping collection |
| Clock/latency | Platform + network team | Source skew, ingestion lag and negative timestamps; align maintenance exceptions |
| Certificates | PKI + platform | Expiry/renewal alarms, failed identity checks, OCSP/CRL reachability where applicable |
| Summary execution | SIEM engineering | Failed/skipped bins, source/result volumes, late arrivals and output freshness |
| Detection pipeline | SOC engineering | Rule execution errors, entity mappings, incident creation and response routing |
| Retention/cost | Service owner + finance | Volume anomalies, tier/retention changes, export/storage bills and legal requirements |

Suggested initial operational thresholds: page on loss of a continuous critical source for 10 minutes; alert on applicable required-field error rates above 1% over a sufficiently populated 15-minute window; notify before certificates reach 30 days to expiry. These are tuning proposals. Low-volume log types, maintenance, normal bursts and scheduled VPN activity require different baselines.

Use an independent monitoring path for collector/ingestion failures; the only alerting mechanism must not depend on the failed stream itself. Record on-call escalation, business impact, evidence retention and recovery verification in the incident procedure.

## 14. Troubleshooting

| Symptom | Safe investigation sequence |
| --- | --- |
| No local PAN-OS events | Check feature/profile enablement, policy match, session timing and expected log family before troubleshooting Azure |
| Local logs but no collector arrival | Check commit/push, forwarding attachments, service/source route, listener port, source restrictions and TLS trust/identity |
| Collector receives but workspace is empty | Check daemon-to-AMA integration, agent health, DCR association, facility/severity selection, Azure egress/private DNS and correct workspace |
| Native CSV arrives but CEF fields are empty | Expected if using `Syslog`; verify the native parser/normalization path, not CEF templates |
| Fields shifted or disappear after an upgrade | Inspect CSV quoting/reserved columns/profile revision and message-length limits; compare retained fixtures |
| Duplicate rows or exaggerated transfer totals | Check replicated destinations, direct-plus-Panorama paths, overlapping DCRs, same-facility collection and start/end accounting |
| Threat/URL/WildFire missing while Traffic works | Check inspection licensing/profiles, matching traffic, log family match lists and forwarding settings |
| VPN success lacks an internal host link | Inspect public/private address assignment, User-ID lifetime, gateway and session time; do not join by public IP alone |
| Unexpected timestamp offsets | Compare device payload time, header time, collector zone and normalization; retain originals for diagnosis |
| Lake data exists but rules stop firing | Inspect table tier and dependencies; restore the approved Analytics path under change control |
| Summary output stale or empty | Check source/schema, supported query/operators, bin delay, execution health and invalid time filters; do not assume no attack occurred |

When collecting diagnostics, bound packet captures/log levels and duration, restrict access and remove temporary tracing afterwards. Never paste full raw configuration records, URL tokens or certificate private keys into support tickets. Microsoft warns that overlapping syslog/CEF collection can duplicate ingestion. [Duplication guidance](https://learn.microsoft.com/en-us/azure/sentinel/cef-syslog-ama-overview#data-ingestion-duplication-avoidance)

## 15. Rollout, rollback and change control

### 15.1 Rollout

1. Approve pattern, data contract, table plan, certificates, costs and test scope.
2. Build collectors and monitoring through reviewed infrastructure/configuration code; keep secrets out of source control.
3. Enable a limited canary without disabling the existing approved security feed. If parallel comparison is necessary, bound its duration and account for intentional duplicates/cost.
4. Validate representative traffic and required management/authentication families; attach the acceptance evidence.
5. Exercise controlled failover/replay and rule-equivalence tests; obtain network, platform and SOC sign-off.
6. Expand in batches with a hold point per batch. Remove temporary dual forwarding only after source counts, detection outcomes and cost reconcile.
7. Monitor during an agreed stabilization window, then approve steady-state ownership and optimization.

### 15.2 Rollback

Rollback triggers include unexplained event loss, failed detections, incorrect identity/time/NAT mapping, runaway duplication/cost, TLS failures and a collector backlog approaching capacity.

Restore only the affected forwarding/DCR/parser/table configuration from the approved baseline. Preserve working ingestion paths and retained raw evidence. Disable or redirect a defective newly introduced path rather than deleting the workspace or its data. Identify in-flight/backlogged records and the resulting gap/duplicate window, then reconcile known source events after recovery.

Table-tier changes and data deletion are not interchangeable rollback steps. Obtain explicit approval for any retention reduction or destructive operation. Confirm that old detections, dashboards and investigation permissions work again before declaring recovery.

### 15.3 Ongoing changes

Treat PAN-OS upgrades, Content hub/parser updates, certificate rotations, security-profile enablement, DCR transformations, collector failover changes and table-tier changes as pipeline changes. Require a schema regression test, dependency check and controlled release. Revisit this guide whenever a vendor's support or ingestion contract changes.

## 16. Handover package

- Approved environment/decision register and architecture, including forwarding source-of-truth.
- Firewall/virtual-system inventory and independent expected-feed inventory.
- PAN-OS profile exports, policy attachments, management log settings and versioned payload manifests.
- Collector infrastructure, TLS/queue configuration, DCRs/associations and network/PKI dependencies.
- Parser implementation, ASIM registration where applicable, sanitized fixtures and expected outputs.
- Physical table schemas, routing transformations, retention/tier settings and privacy approvals.
- Detection dependency matrix, ATT&CK rationale, entity mappings and safe positive/negative test results.
- Ingestion/failover/latency/cost acceptance evidence with approvers and dates.
- Health alerts, on-call ownership, certificate renewal, rollback and disaster-recovery procedures.

Outstanding until supplied: actual production inventory, deployed PAN-OS versions, collector sizing, certificates, schemas/parsers, policy/profile exports, table/tier approval and executed acceptance results. This document does not substitute for those deployable configurations or evidence.

## 17. References

Sources checked on 21 October 2026. Vendor pages may change; retain approved schema/profile revisions with the implementation. Product documentation takes precedence over this guide for supported features. Sumo's guide is a useful collection reference, not a Sentinel parser specification.

### Palo Alto Networks

- [CEF support status](https://docs.paloaltonetworks.com/resources/cef)
- [Configure syslog monitoring](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/configure-syslog-monitoring)
- [Syslog field catalogue](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions)
- [Traffic fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields)
- [Threat fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields)
- [Configuration fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/config-log-fields)
- [Authentication fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/authentication-log-fields)
- [GlobalProtect fields](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/globalprotect-log-fields)
- [Log Forwarding profiles](https://docs.paloaltonetworks.com/network-security/security-policy/administration/objects/log-forwarding)

### Microsoft

- [Syslog and CEF AMA architecture](https://learn.microsoft.com/en-us/azure/sentinel/cef-syslog-ama-overview)
- [AMA connector setup](https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-syslog-ama)
- [AMA network configuration](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-network-configuration)
- [Data collection endpoint requirements](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-endpoint-overview)
- [CEF field mapping](https://learn.microsoft.com/en-us/azure/sentinel/cef-name-mapping)
- [CommonSecurityLog schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/commonsecuritylog)
- [Syslog schema and table capabilities](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/syslog)
- [CEF and syslog troubleshooting](https://learn.microsoft.com/en-us/azure/sentinel/cef-syslog-ama-troubleshooting)
- [ASIM parser catalogue](https://learn.microsoft.com/en-us/azure/sentinel/normalization-parsers-list)
- [ASIM usage](https://learn.microsoft.com/en-us/azure/sentinel/normalization-about-parsers)
- [ASIM Network Session schema](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-network)
- [Kusto parse_csv](https://learn.microsoft.com/en-us/kusto/query/parse-csv-function)
- [Sentinel table tiers and retention](https://learn.microsoft.com/en-us/azure/sentinel/manage-data-overview)
- [Summary rules](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/summary-rules)
- [Lake KQL jobs, summary rules and search jobs](https://learn.microsoft.com/en-us/azure/sentinel/datalake/kql-jobs-summary-rules-search-jobs)

### Additional collection reference

- [Sumo Logic: Palo Alto firewall ingestion](https://www.sumologic.com/help/docs/cse/ingestion/ingestion-sources-for-cloud-siem/palo-alto-firewall/): reviewed for collection breadth. Its `_parser` and `_siemForward` settings are Sumo-specific. Do not copy custom positional templates without validation against the actual receiver and PAN-OS version.

### MITRE ATT&CK

- [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1071.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [T1686.002 Network Device Firewall](https://attack.mitre.org/techniques/T1686/002/)
