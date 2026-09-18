# MemSentry Live Observation & Correlation
## Technical Proposal and Implementation Plan

**Project:** MemSentry  
**Document Type:** Technical Proposal  
**Status:** Proposed  
**Version:** 1.0  
**Date:** 2026-09-14

---

## 1. Executive Summary

MemSentry is currently planned as a cross-platform digital forensics application capable of importing memory dumps, performing live memory acquisition, analyzing captured memory with Volatility 3, scanning artifacts with YARA, and correlating forensic evidence through deterministic correlation rules.

This proposal extends that architecture with a **Live Observation and Behavioral Correlation** capability.

The proposed capability will allow MemSentry to observe selected process and system activities while the operating system is running, normalize those observations into a common evidence model, correlate related events, and display the resulting relationships in a live graph and timeline.

The feature is intended to complement—not replace—the existing memory acquisition and forensic analysis pipeline.

The resulting investigation workflow will be:

> **Observe → Detect → Correlate → Visualize → Capture → Analyze → Correlate Again**

This creates a continuous investigation path between live behavior and post-acquisition memory forensics.

---

# 2. Objectives

The proposed feature has the following objectives:

1. Observe process activity in real time.
2. Track relationships between processes and other system artifacts.
3. Normalize Windows and Linux telemetry into a common event model.
4. Feed observed evidence into the existing correlation engine.
5. Preserve observed evidence separately from inferred relationships.
6. Display relationships through a live graph.
7. Provide a chronological investigation timeline.
8. Allow suspicious behavior to trigger or suggest memory acquisition.
9. Connect live observations with subsequent memory-dump analysis.
10. Integrate YARA and Volatility results into the same investigation graph.
11. Maintain compatibility with the existing portable MemSentry architecture.
12. Preserve independent use of imported dumps and live memory acquisition.

---

# 3. Scope

## 3.1 In Scope

### Live observation

Initial observation capabilities should include:

- Process creation
- Process termination
- Process execution
- Module loading
- Module unloading
- File creation
- File modification/write
- File deletion
- File rename
- Network connections
- Network listeners
- Process access
- Memory-related activity where supported by the operating system telemetry source

### Evidence processing

- Event normalization
- Process-instance tracking
- Evidence storage
- Relationship creation
- Correlation-rule evaluation
- Timeline construction
- Graph construction
- Provenance tracking

### Forensic integration

- Live memory acquisition
- Imported memory dumps
- Volatility 3 analysis
- YARA analysis
- Correlation of live and post-acquisition evidence

### Visualization

- Live process/evidence graph
- Timeline
- Process details
- Correlation findings
- Evidence provenance
- Memory-capture actions

---

## 3.2 Out of Scope for Initial Version

The first implementation should not attempt to:

- Monitor every operating-system event.
- Replace Volatility 3.
- Replace dedicated endpoint detection systems.
- Automatically classify every suspicious event as malware.
- Implement unrestricted kernel-level monitoring.
- Build a complete SIEM platform.
- Automatically perform invasive response actions.
- Treat behavioral correlations as definitive malware verdicts.

These capabilities can be considered later if required.

---

# 4. Architectural Principles

The feature must follow several principles established by the existing MemSentry architecture.

## 4.1 Volatility remains a forensic analysis engine

Volatility 3 should continue to be used primarily for analysis of captured memory.

It should not become the primary live-monitoring mechanism.

The separation is:

```text
Live Observation
       ↓
Telemetry / Events
       ↓
Evidence Model

Memory Acquisition
       ↓
Memory Dump
       ↓
Volatility 3
```

---

## 4.2 Raw observations must remain separate from inference

MemSentry must preserve the difference between:

### Observed evidence

Example:

```text
powershell.exe created script.ps1
```

### Correlation

Example:

```text
powershell.exe created script.ps1
+
powershell.exe executed script.ps1
```

### Assessment

Example:

```text
The observed sequence is suspicious.
```

The system must never overwrite the original observation with a derived conclusion.

---

## 4.3 Every relationship must have provenance

A graph edge should be traceable to its source evidence.

For example:

```text
powershell.exe
      │
      └── CONNECTS_TO ──> 10.0.0.5:443
```

The relationship should reference the event that caused the edge to exist.

Conceptually:

```python
Relationship(
    source_id="proc-123",
    relation="CONNECTS_TO",
    target_id="net-456",
    timestamp="...",
    source="live_telemetry",
    evidence_id="evt-789"
)
```

This allows an investigator to answer:

> Why does this relationship exist?

---

# 5. High-Level Architecture

```text
                           MEMSENTRY
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
        ▼                      ▼                      ▼
   LIVE MONITORING       MEMORY ACQUISITION      IMPORT DUMP
        │                      │                      │
        ▼                      ▼                      ▼
   OS ADAPTERS             DUMP MANAGER          FILE INPUT
        │                      │                      │
        └──────────────┬───────┴──────────────┬───────┘
                       ▼                      ▼
                EVENT / EVIDENCE MODEL    MEMORY IMAGE
                       │                      │
                       │                 ┌────┴─────┐
                       │                 ▼          ▼
                       │            VOLATILITY    YARA
                       │                 │          │
                       └────────────┬────┴──────────┘
                                    ▼
                           CORRELATION ENGINE
                                    │
                              ┌─────┴─────┐
                              ▼           ▼
                          TIMELINE      GRAPH
                              │           │
                              └─────┬─────┘
                                    ▼
                              MEMSENTRY UI
                                    │
                              INVESTIGATION
                                    │
                              FINAL REPORT
```

---

# 6. Integration With Existing MemSentry

The current application should retain its existing workflows.

## 6.1 Imported memory dump

```text
Import Dump
    ↓
Dump Manager
    ↓
Volatility 3
    ↓
Plugin Runner
    ↓
YARA
    ↓
Correlation Engine
    ↓
Graph / Timeline
    ↓
Report
```

## 6.2 Live memory acquisition

```text
Start Live Acquisition
    ↓
OS-specific Dump Manager
    ↓
Memory Dump
    ↓
Volatility 3
    ↓
YARA
    ↓
Correlation Engine
    ↓
Graph / Timeline
```

## 6.3 Live observation

```text
Start Live Monitoring
    ↓
OS-specific Telemetry Adapter
    ↓
Event Normalizer
    ↓
Evidence Store
    ↓
Correlation Engine
    ↓
Live Graph / Timeline
```

These three workflows eventually converge through the evidence and correlation layers.

---

# 7. Proposed Project Structure

The existing structure can be extended as follows:

```text
memsentry/
│
├── acquisition/
│   ├── dump_manager.py
│   ├── progress.py
│   └── adapters/
│       ├── windowsDumpManager.py
│       ├── linuxDumpManager.py
│       └── macDumpManager.py
│
├── observation/
│   ├── monitor.py
│   ├── event_bus.py
│   ├── normalizer.py
│   ├── process_tracker.py
│   └── adapters/
│       ├── windows/
│       │   ├── process_observer.py
│       │   ├── file_observer.py
│       │   ├── network_observer.py
│       │   └── module_observer.py
│       │
│       ├── linux/
│       │   ├── process_observer.py
│       │   ├── file_observer.py
│       │   ├── network_observer.py
│       │   └── module_observer.py
│       │
│       └── mac/
│           └── ...
│
├── evidence/
│   ├── event.py
│   ├── process.py
│   ├── artifact.py
│   ├── relationship.py
│   └── store.py
│
├── correlation/
│   ├── engine.py
│   ├── rule_loader.py
│   ├── correlation_rules.yaml
│   └── evaluators/
│
├── yara/
│   ├── engine.py
│   ├── rule_loader.py
│   └── rules/
│
├── volatility/
│   ├── plugin_runner.py
│   ├── plugin_registry.py
│   ├── symbol_manager.py
│   └── ...
│
└── graph/
    ├── graph_builder.py
    ├── graph_model.py
    └── timeline.py
```

This represents the target architecture rather than a requirement to implement every module immediately.

---

# 8. Common Observation Event Model

A common event model is fundamental to cross-platform support.

Windows and Linux telemetry sources may expose different native information. The OS-specific adapters should convert those native events into a common MemSentry representation.

Example:

```python
class ObservationEvent:
    event_id: str
    timestamp: datetime
    host_id: str
    os: str

    event_type: str

    pid: int | None
    ppid: int | None

    process_name: str | None
    process_path: str | None

    source: str

    metadata: dict
```

Example event:

```json
{
  "event_type": "PROCESS_CREATE",
  "pid": 4128,
  "ppid": 1092,
  "process_name": "powershell.exe",
  "process_path": "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
  "source": "windows_telemetry"
}
```

The correlation engine should consume this normalized representation rather than being tightly coupled to individual operating systems.

---

# 9. Initial Event Types

The initial release should focus on high-value events.

## 9.1 Process events

```text
PROCESS_CREATE
PROCESS_EXIT
PROCESS_EXEC
```

## 9.2 Module events

```text
MODULE_LOAD
MODULE_UNLOAD
```

## 9.3 File events

```text
FILE_CREATE
FILE_WRITE
FILE_DELETE
FILE_RENAME
```

## 9.4 Network events

```text
NETWORK_CONNECT
NETWORK_LISTEN
NETWORK_CLOSE
```

## 9.5 Memory events

Where the selected telemetry source provides appropriate visibility:

```text
MEMORY_ALLOCATE
MEMORY_PROTECT
MEMORY_MAP
```

## 9.6 Process interaction

Where supported:

```text
PROCESS_ACCESS
PROCESS_INJECTION
REMOTE_THREAD
```

Not every event type will necessarily be available on every operating system.

The event model should therefore distinguish between:

```text
Supported
Unsupported
Unknown
```

rather than assuming identical visibility across platforms.

---

# 10. Process Identity

PID alone must not be treated as a permanent process identity because operating systems can reuse process IDs.

MemSentry should introduce:

```text
process_instance_id
```

A conceptual identity can be based on:

```text
host
+
PID
+
process start time
```

For example:

```text
PID = 4128
Start = 2026-09-14 02:41:10

process_instance_id =
hash(host + pid + start_time)
```

This allows the graph and evidence store to distinguish different processes that happened to reuse the same PID.

---

# 11. Evidence Model

The evidence layer should contain distinct entities.

## 11.1 Process

```text
Process
├── process_instance_id
├── PID
├── PPID
├── name
├── executable path
├── command line
├── user
├── start time
├── end time
└── hash
```

## 11.2 Artifact

Possible artifacts include:

```text
File
Network Endpoint
Module
Memory Region
Registry Key
Service
User
```

## 11.3 Relationship

Relationships should include:

```text
source
relation
target
timestamp
evidence_id
source_type
confidence
```

Possible relationships:

```text
CREATES
SPAWNS
OPENS
WRITES
DELETES
LOADS
CONNECTS_TO
LISTENS_ON
ACCESSES
ALLOCATES
MODIFIES
INJECTS_INTO
```

---

# 12. Correlation Engine Integration

The existing deterministic correlation engine should be extended rather than replaced.

Existing rules such as memory-related correlations can remain.

Additional behavioral rules can be introduced.

Conceptual examples:

```yaml
rules:

  - id: MS-R001
    name: Executable private memory
    ...

  - id: MS-R010
    name: Suspicious process chain
    ...

  - id: MS-R011
    name: Process writes executable then executes
    ...

  - id: MS-R012
    name: Application creates shell
    ...

  - id: MS-R013
    name: Suspicious process network activity
    ...
```

The correlation engine should produce findings based on observed evidence.

It should not directly declare:

```text
process = malware
```

Instead, it should produce an explainable finding such as:

```text
Correlation MS-R011 matched.

Evidence:
1. Process A created file X.
2. Process A subsequently executed file X.
3. Events occurred within the correlation window.
```

---

# 13. Evidence, Correlation, and Assessment Layers

MemSentry should maintain three logical layers.

```text
┌──────────────────────────────┐
│ OBSERVATION                  │
│ What was actually observed   │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│ CORRELATION                  │
│ What relationships were found│
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│ ASSESSMENT                   │
│ What the evidence suggests   │
└──────────────────────────────┘
```

This makes findings explainable and auditable.

---

# 14. Graph Architecture

The graph should be an **evidence graph**, not merely a process tree.

## 14.1 Node types

```text
PROCESS
FILE
NETWORK_ENDPOINT
MODULE
MEMORY_REGION
REGISTRY_KEY
USER
SERVICE
```

## 14.2 Edge types

```text
CREATES
SPAWNS
WRITES
LOADS
CONNECTS_TO
ACCESSES
ALLOCATES
INJECTS_INTO
MODIFIES
```

## 14.3 Example

```text
             explorer.exe
                  │
                SPAWNS
                  ↓
           suspicious.exe
             │      │
           LOADS  CONNECTS_TO
             │      │
             ↓      ↓
          evil.dll  10.0.0.5:443
             │
          MATCHES
             ↓
          YARA Rule
```

Every edge should remain traceable to the underlying evidence event.

---

# 15. Live Graph Behaviour

The graph should update incrementally as events arrive.

Example:

```text
02:41:10
explorer.exe starts

02:41:13
explorer.exe → creates → suspicious.exe

02:41:13
suspicious.exe → loads → abc.dll

02:41:14
suspicious.exe → connects → 10.0.0.5:443

02:41:15
suspicious.exe → modifies → memory region
```

The graph receives logical updates such as:

```text
ADD_NODE
ADD_EDGE
UPDATE_NODE
UPDATE_EDGE
ALERT
```

The UI should not need to rebuild the entire graph for every event.

---

# 16. Timeline

The graph answers:

> What is related?

The timeline answers:

> What happened and in what order?

Example:

```text
02:41:10  Process created
02:41:13  Child process created
02:41:13  Module loaded
02:41:14  Network connection
02:41:15  Memory activity
```

Graph and timeline interactions should be connected.

Selecting an edge should reveal its corresponding event.

Selecting an event should highlight the associated graph nodes and edges.

---

# 17. Live Detection and Memory Acquisition

One of the most important integrations is connecting suspicious live behavior to the existing acquisition layer.

Example:

```text
Process behavior observed
        ↓
Correlation rule triggered
        ↓
Suspicious finding
        ↓
Investigator selects "Capture Memory"
        ↓
Existing dump manager
        ↓
Memory dump
        ↓
Volatility + YARA
        ↓
Additional correlations
```

The system should not automatically perform invasive actions without an explicit policy and authorization.

The initial UI can simply provide:

```text
[Investigate]
[Capture Memory]
```

---

# 18. Investigation Session

A single investigation should provide a common identity across live and post-acquisition evidence.

Example:

```text
investigation_id = INV-2026-001
```

Live event:

```text
event_id = EVT-10023
process_instance_id = PROC-502
```

Memory capture:

```text
dump_id = DUMP-009
captured_at = 02:41:20
```

Volatility and YARA results can then be associated with the same investigation and, where possible, the same process instance.

Conceptually:

```text
Live Evidence
      │
      ▼
PROC-502
      │
      ├── Live Events
      │
      └── Memory Evidence
              │
              ├── Volatility results
              ├── YARA matches
              ├── VAD evidence
              ├── Module evidence
              └── Network evidence
```

---

# 19. YARA Integration

YARA should remain a pattern/signature analysis component.

Suitable uses include:

- Memory pattern scanning
- Suspicious strings
- Known malware patterns
- File content scanning
- Extracted artifact scanning
- Suspicious/injected memory scanning

Behavioral correlation remains the responsibility of the correlation engine.

The architecture becomes:

```text
Live Behavior
      +
Memory Evidence
      +
YARA Match
      ↓
Correlation Engine
      ↓
Explainable Finding
```

---

# 20. Volatility Integration

The existing Volatility architecture should remain.

Existing components such as:

```text
PluginRegistry
PluginRunner
SymbolManager
```

continue to serve the memory-analysis workflow.

Example:

```text
Memory Dump
    ↓
Plugin Runner
    ↓
Selected Volatility Plugins
    ↓
Results
    ↓
Evidence Model
    ↓
Correlation Engine
```

Live telemetry can be used to determine which forensic information is most relevant after a capture.

For example:

```text
Observed:
Possible process injection

        ↓

Prioritize:
Process information
Memory mappings
Loaded modules
Process handles
Network information
YARA scanning
```

This can reduce unnecessary analysis.

---

# 21. Portable Deployment

The proposed feature must remain compatible with the planned portable MemSentry deployment.

A conceptual portable layout is:

```text
MemSentry/
│
├── MemSentry.exe
│
├── engines/
│
├── tools/
│   ├── windows/
│   ├── linux/
│   └── mac/
│
├── rules/
│   ├── yara/
│   └── correlation_rules.yaml
│
├── symbols/
│
├── cases/
│
└── config/
```

The application should determine the current operating system and load the appropriate telemetry and acquisition adapter.

The portable package should not assume that every OS-specific tool is available or usable.

The application should explicitly report states such as:

```text
Supported
Unavailable
Not installed
Insufficient privileges
Unsupported on this platform
```

---

# 22. Privilege Architecture

Live observation may require elevated privileges for some event classes.

The application should avoid making the entire user interface unnecessarily privileged.

A conceptual separation is:

```text
MemSentry UI
      │
      ▼
Observation Service
      │
      ├── Normal telemetry
      │
      └── Privileged telemetry
```

This provides better separation of concerns and reduces the privilege footprint of the main application.

---

# 23. Evidence Storage

Each investigation should preserve raw observations, derived relationships, analysis results, and acquired dumps separately.

Example:

```text
cases/
└── INV-2026-001/
    ├── metadata.json
    ├── events/
    │   ├── events.ndjson
    │   └── raw/
    │
    ├── evidence/
    │
    ├── correlations/
    │
    ├── yara/
    │
    ├── volatility/
    │
    ├── dumps/
    │
    └── graph/
```

The exact serialization format can be finalized during implementation.

The important requirement is preservation of:

```text
Raw observation
      ≠
Derived relationship
      ≠
Assessment
```

---

# 24. User Interface Proposal

The main investigation interface should contain four primary areas.

```text
┌─────────────────────────────────────────────────────┐
│ MemSentry                                            │
├────────────┬────────────────────────────────────────┤
│            │                                        │
│ Overview   │              LIVE GRAPH               │
│            │                                        │
│ Live       │      Process → File → Network         │
│ Monitor    │                                        │
│            │                                        │
│ Processes  │                                        │
│            │                                        │
│ Evidence   │                                        │
│            │                                        │
│ Correlation│                                        │
│            │                                        │
│ Dumps      │                                        │
├────────────┴────────────────────────────────────────┤
│ Timeline                                             │
│ 02:41:10 Process created                             │
│ 02:41:13 Module loaded                              │
│ 02:41:14 Network connection                         │
└─────────────────────────────────────────────────────┘
```

---

# 25. Process Details

Selecting a process should show:

```text
Process Details
────────────────────────
PID
PPID
Process instance ID
Path
Command line
Hash
User
Start time
End time

Observed Activity
Correlations
YARA Results
Memory Evidence

[Capture Memory]
```

This provides an investigator-oriented workflow without forcing them to inspect raw telemetry manually.

---

# 26. Example End-to-End Scenario

Consider the following activity:

```text
explorer.exe
      │
      └── creates → suspicious.exe
                         │
                         ├── loads → suspicious.dll
                         │
                         ├── writes → temp.ps1
                         │
                         ├── executes → temp.ps1
                         │
                         └── connects → external endpoint
```

The correlation engine identifies a behavioral chain.

The UI displays:

```text
Suspicious Behavior Detected

Process:
suspicious.exe

Observed:
- Suspicious child process relationship
- Module loaded
- Script created
- Script executed
- Network connection

Correlation:
MS-R011
MS-R013

Actions:
[Investigate]
[Capture Memory]
```

If the investigator captures memory:

```text
Memory Dump
    ↓
Volatility
    ↓
YARA
    ↓
Additional Evidence
    ↓
Correlation
    ↓
Updated Graph
```

The final graph can combine both live and memory evidence.

---

# 27. Implementation Phases

## Phase 1 — Common Data Model

Implement:

```text
ObservationEvent
ProcessInstance
Artifact
Relationship
Evidence
Investigation
```

### Deliverable

A platform-independent evidence model that can accept synthetic events.

---

## Phase 2 — Process Observation

Implement:

```text
PROCESS_CREATE
PROCESS_EXIT
PROCESS_EXEC
```

### Deliverable

A working live process tree and event stream.

---

## Phase 3 — File and Network Observation

Implement:

```text
FILE_CREATE
FILE_WRITE
FILE_DELETE
FILE_RENAME

NETWORK_CONNECT
NETWORK_LISTEN
NETWORK_CLOSE
```

### Deliverable

Process → File → Network relationships.

---

## Phase 4 — Graph Engine

Implement:

```text
Graph nodes
Graph edges
Evidence references
Incremental updates
Timeline integration
```

### Deliverable

A live evidence graph.

---

## Phase 5 — Correlation Integration

Connect normalized observation events to the existing correlation engine.

### Deliverable

Live behavioral correlation findings using the existing rule architecture.

---

## Phase 6 — Memory-Related Observation

Where supported:

```text
MEMORY_ALLOCATE
MEMORY_PROTECT
PROCESS_ACCESS
REMOTE_THREAD
```

### Deliverable

Memory-related behavioral evidence that can strengthen correlations.

---

## Phase 7 — Capture-on-Investigation

Connect suspicious findings to:

```text
acquisition.dump_manager
```

### Deliverable

Investigator-triggered memory acquisition from the live investigation view.

---

## Phase 8 — Volatility and YARA Enrichment

After acquisition:

```text
Dump
 ↓
Volatility
 ↓
YARA
 ↓
Evidence
 ↓
Correlation
 ↓
Graph
```

### Deliverable

Combined live and memory evidence.

---

## Phase 9 — Unified Investigation Timeline

Merge:

```text
Live Events
+
Memory Evidence
+
Volatility Results
+
YARA Results
+
Correlation Findings
```

### Deliverable

A unified forensic investigation timeline.

---

# 28. Testing Strategy

Testing should be performed at several levels.

## Unit tests

Test:

- Event normalization
- Process identity
- Relationship creation
- Correlation rules
- Evidence serialization
- Graph updates

## Integration tests

Test:

```text
Telemetry
    ↓
Normalizer
    ↓
Evidence
    ↓
Correlation
    ↓
Graph
```

And:

```text
Correlation
    ↓
Acquisition
    ↓
Volatility
    ↓
YARA
    ↓
Correlation
```

## Cross-platform tests

At minimum:

```text
Windows
Linux
```

with macOS support following the same adapter model if included in the final product scope.

## Performance tests

Measure:

- Event throughput
- CPU utilization
- Memory utilization
- Graph update latency
- Evidence storage rate
- Correlation processing latency

---

# 29. Security and Reliability Requirements

The live-monitoring subsystem should:

1. Minimize required privileges.
2. Validate all external telemetry data.
3. Avoid executing arbitrary event-derived commands.
4. Keep raw evidence immutable where practical.
5. Record timestamps consistently.
6. Handle dropped or unavailable events explicitly.
7. Avoid silently claiming complete visibility.
8. Record telemetry source and limitations.
9. Prevent graph relationships from becoming untraceable derived data.
10. Ensure acquisition actions require appropriate user authorization.

---

# 30. Performance Considerations

Live telemetry can generate a large volume of events.

Therefore the architecture should use:

```text
OS Adapter
    ↓
Event Queue / Event Bus
    ↓
Normalizer
    ↓
Filtering
    ↓
Evidence Store
    ↓
Correlation
    ↓
Graph
```

The graph should not necessarily display every low-level event.

The evidence store can retain detailed events while the UI presents meaningful relationships.

This provides:

```text
Full evidence
    +
Reduced visual complexity
```

---

# 31. Future Enhancements

After the initial implementation is stable, potential enhancements include:

- Advanced process behavior scoring
- More memory telemetry
- Kernel-level observation where appropriate
- Automatic forensic plugin selection
- Investigation replay
- Graph filtering
- Graph time-window controls
- Process-centric investigation mode
- Network-centric investigation mode
- Automated report generation
- Evidence export
- Investigation comparison
- Remote observation
- Alert policies
- Additional operating-system adapters

These should remain separate from the initial implementation to avoid excessive complexity.

---

# 32. Final Proposed Workflow

The final MemSentry investigation model is:

```text
                     START INVESTIGATION
                              │
                 ┌────────────┴────────────┐
                 │                         │
                 ▼                         ▼
          LIVE OBSERVATION          IMPORT / ACQUIRE
                 │                     MEMORY
                 │                         │
                 ▼                         ▼
             EVENTS                  MEMORY IMAGE
                 │                         │
                 ▼                         ▼
          NORMALIZATION              VOLATILITY
                 │                         │
                 └───────────┬─────────────┘
                             ▼
                       EVIDENCE MODEL
                             │
                  ┌──────────┼──────────┐
                  ▼          ▼          ▼
             CORRELATION   YARA      ANALYSIS
                  │          │          │
                  └──────────┼──────────┘
                             ▼
                    CORRELATION ENGINE
                             │
                       ┌─────┴─────┐
                       ▼           ▼
                    GRAPH       TIMELINE
                       │           │
                       └─────┬─────┘
                             ▼
                       INVESTIGATOR
                             │
                    ┌────────┴────────┐
                    ▼                 ▼
                Investigate       Capture Memory
                                      │
                                      ▼
                                  FORENSIC
                                  ANALYSIS
                                      │
                                      ▼
                               UPDATED EVIDENCE
                                      │
                                      ▼
                                  FINAL GRAPH
```

---

# 33. Key Architectural Decisions

The following decisions should be treated as the foundation of this feature:

1. **Live monitoring is a new observation subsystem, not a replacement for Volatility.**
2. **OS-specific telemetry is isolated behind adapters.**
3. **All telemetry is normalized into a common MemSentry event model.**
4. **PID alone is never used as a permanent process identity.**
5. **Raw observations remain separate from inferred relationships.**
6. **Every graph relationship has evidence provenance.**
7. **The correlation engine produces explainable findings rather than automatic malware verdicts.**
8. **YARA remains a pattern/signature analysis component.**
9. **Volatility remains the primary post-acquisition memory-analysis engine.**
10. **Live observation can lead to investigator-authorized memory acquisition.**
11. **Imported dumps and live acquisition remain independently usable.**
12. **The graph is a visualization of the evidence model, not the evidence store itself.**
13. **The investigation ID connects live, acquisition, Volatility, YARA, and correlation evidence.**
14. **The UI should expose both relationship context and chronological context.**
15. **The first version should prioritize reliable, explainable evidence collection over maximum telemetry coverage.**

---

# 34. Conclusion

Adding Live Observation and Correlation will significantly extend MemSentry from a memory-forensics application into a broader investigation platform while preserving its existing architecture.

The proposed design does not require replacing the current:

- Acquisition layer
- Dump managers
- Volatility integration
- Plugin runner
- Symbol manager
- YARA engine
- Correlation rules
- Portable deployment model

Instead, it introduces a new live-observation path that feeds the same evidence and correlation architecture.

The central concept is:

> **MemSentry should observe live behavior, preserve the observations as evidence, correlate related artifacts, visualize those relationships, and allow the investigator to transition from live behavior into memory forensics.**

This provides a technically coherent foundation for a live process-behavior graph while maintaining the forensic integrity and modularity of the existing MemSentry design.
