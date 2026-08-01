## Core functionality for MemSentry

### 1. Case management

* Create a new investigation case.
* Enter case ID, investigator name, description, and notes.
* Select a dedicated output directory.
* Open and continue an existing case.
* Record case creation and modification timestamps.
* Prevent duplicate case IDs.
* Maintain a case manifest containing all analysis settings.
* Record chain-of-custody information.
* Export case metadata.

### 2. Memory image selection

* Select a previously acquired memory image.
* Support common formats such as:

  * `.raw`
  * `.mem`
  * `.dmp`
* Display:

  * file name;
  * full path;
  * file size;
  * creation and modification times;
  * detected or selected operating system.
* Validate that the file exists and is readable.
* Warn when the format is unsupported.
* Open evidence in read-only mode.
* Never modify the original memory image.

### 3. Evidence integrity verification

* Calculate SHA-256 before analysis.
* Display hashing progress.
* Record hash duration and file size.
* Calculate SHA-256 again after analysis.
* Compare pre-analysis and post-analysis hashes.
* Clearly show:

  * Verified;
  * Mismatch;
  * Not completed.
* Store hash results in the case manifest.
* Generate a checksum file for exported reports.
* Warn the investigator if evidence integrity cannot be verified.

### 4. Environment and dependency checks

* Check whether Volatility 3 is available.
* Display the Volatility version.
* Check Python and application versions.
* Verify access to the symbols directory.
* Verify output-directory permissions.
* Check available disk space.
* Check available system memory.
* Verify YARA support.
* Verify report templates and correlation rules.
* Show readiness status before analysis begins.

### 5. Analysis configuration

* Allow the investigator to select analysis plugins.
* Provide a recommended default plugin set.
* Allow optional YARA rule selection.
* Select or configure a symbol directory.
* Configure plugin timeout limits.
* Select whether failed plugins should stop or continue the analysis.
* Save the selected configuration with the case.
* Allow configurations to be reused.
* Display an estimated analysis plan before starting.

### 6. Volatility 3 plugin execution

The initial application should support:

* `windows.info`
* `windows.pslist`
* `windows.pstree`
* `windows.cmdline`
* `windows.netscan`
* `windows.malfind`
* `windows.dlllist`
* `windows.threads`

Additional plugins can include:

* `windows.handles`
* `windows.modules`
* `windows.vadinfo`
* `windows.filescan`
* `windows.envars`
* `windows.getsids`
* `windows.svcscan`
* `windows.registry.hivelist`

For each plugin, record:

* plugin name;
* command parameters;
* start time;
* completion time;
* execution duration;
* exit code;
* row count;
* warnings;
* errors;
* output file;
* Volatility version.

### 7. Analysis progress monitoring

* Show overall progress.
* Show the currently running plugin.
* Display completed, failed, skipped, and pending plugins.
* Show elapsed analysis time.
* Display live diagnostic messages.
* Allow the investigator to cancel the analysis.
* Preserve already completed outputs after cancellation.
* Clearly mark an incomplete analysis.
* Keep the GUI responsive during long-running tasks.

### 8. Plugin failure handling

* Detect plugin crashes.
* Detect plugin timeouts.
* Detect missing symbols.
* Detect malformed output.
* Show user-friendly error messages.
* Preserve technical error details in logs.
* Continue with independent plugins when appropriate.
* Mark affected findings as incomplete.
* Include failures in the final report.
* Never silently ignore failed analysis stages.

### 9. Raw output preservation

* Save the original output from each Volatility plugin.
* Preserve stdout and stderr separately.
* Store outputs in the case directory.
* Record hashes of raw output files.
* Allow investigators to open raw outputs.
* Keep raw outputs unchanged after creation.
* Link normalized artifacts back to their original rows.
* Record plugin parameters and tool versions.

### 10. Artifact normalization

Convert plugin outputs into consistent entities such as:

* Process
* Thread
* Memory region
* Module
* Network connection
* YARA match
* Handle
* Service
* File object
* Registry artifact
* Evidence relationship

For each normalized artifact, preserve:

* unique artifact ID;
* original values;
* normalized values;
* source plugin;
* source row;
* extraction timestamp;
* plugin parameters;
* related process ID;
* related memory address;
* confidence or completeness status.

### 11. Process explorer

* Display all discovered processes.
* Show:

  * PID;
  * PPID;
  * process name;
  * command line;
  * creation time;
  * exit time;
  * risk score;
  * YARA matches;
  * network connections;
  * executable memory regions;
  * triggered rules.
* Sort and filter processes.
* Search by process name or PID.
* Filter by risk level.
* Open detailed process information.
* Export selected process details.

### 12. Process tree visualization

* Display parent-child process relationships.
* Expand and collapse process branches.
* Highlight suspicious processes.
* Show terminated and active processes differently.
* Detect orphaned processes.
* Highlight unusual parent-child combinations.
* Open process details by selecting a node.
* Export the process tree.

### 13. Memory-region analysis

* Display memory regions associated with each process.
* Show:

  * start address;
  * end address;
  * size;
  * protection;
  * private or mapped status;
  * mapped file;
  * executable status.
* Highlight writable and executable regions.
* Highlight private executable regions.
* Link regions to `malfind` results.
* Link regions to YARA matches.
* Link thread start addresses to memory regions.
* Display possible benign explanations such as JIT compilation.

### 14. Network connection analysis

* Display network connections.
* Show:

  * owning PID;
  * process name;
  * protocol;
  * local address;
  * local port;
  * remote address;
  * remote port;
  * connection state.
* Search and filter connections.
* Group connections by process.
* Highlight external connections.
* Correlate network activity with suspicious memory regions.
* Never contact or resolve discovered endpoints automatically.
* Export connection data.

### 15. Module and DLL analysis

* Display loaded modules and DLLs for each process.
* Show module path and base address.
* Identify modules without normal file paths.
* Identify modules loaded from unusual directories.
* Link modules to processes and memory regions.
* Highlight modules related to suspicious findings.
* Preserve the original Volatility values.
* Avoid declaring a module malicious based on path alone.

### 16. Thread analysis

* Display threads associated with each process.
* Show thread ID and start address.
* Link thread start addresses to memory regions.
* Highlight threads starting in private executable regions.
* Show missing or incomplete thread information.
* Correlate suspicious threads with YARA matches.
* Include supporting thread evidence in findings.

### 17. YARA analysis

* Import user-provided YARA rules.
* Validate YARA syntax before analysis.
* Display compilation errors.
* Record YARA rule file hash.
* Record the selected rule-set version.
* Run approved YARA scans.
* Display:

  * matched rule;
  * process;
  * memory region;
  * address;
  * namespace;
  * tags.
* Link YARA matches to related processes and regions.
* Include matched rules in reports.
* Do not treat a YARA match alone as proof of malware.

### 18. Correlation engine

* Link artifacts using:

  * PID;
  * PPID;
  * thread ID;
  * memory address;
  * module base address;
  * connection ownership;
  * YARA match location.
* Combine indicators from multiple plugins.
* Generate process-level findings.
* Preserve all evidence supporting each finding.
* Separate observed evidence from inferred relationships.
* Produce deterministic results.
* Record the rule version used.
* Allow findings to be regenerated from saved normalized artifacts.

### 19. Detection rules

Initial rules may include:

* Private executable memory.
* Writable and executable memory.
* Thread start address inside private executable memory.
* YARA match inside a suspicious memory region.
* Suspicious memory combined with network activity.
* Unusual parent-child process relationship.
* Process with suspicious memory and unusual module loading.
* Process hidden from one process listing but visible in another.
* Command-line behavior inconsistent with the process type.
* Multiple weak indicators affecting the same process.

Each rule should include:

* rule ID;
* name;
* description;
* score;
* severity;
* required evidence;
* benign explanations;
* limitations;
* version;
* enabled or disabled status.

### 20. Explainable risk scoring

* Calculate a process-level risk score.
* Show the contribution of each rule.
* Display the supporting artifacts.
* Explain why a score increased.
* Show possible benign explanations.
* Avoid presenting a score as proof of maliciousness.
* Use categories such as:

  * Informational;
  * Low;
  * Medium;
  * High;
  * Critical.
* Allow configurable rule weights.
* Record customized scoring configurations.
* Distinguish default scoring from analyst-modified scoring.

### 21. Confidence and completeness

* Show evidence confidence separately from risk.
* Show analysis completeness.
* Identify missing plugin outputs.
* Identify missing symbol support.
* Reduce confidence when important artifacts are unavailable.
* Display statuses such as:

  * Complete;
  * Partial;
  * Inconclusive.
* Explain why confidence is limited.
* Include completeness information in reports.

### 22. Counter-evidence and benign explanations

* Identify evidence that may reduce suspicion.
* Show possible JIT-related memory behavior.
* Identify common browser, Java, Python, or .NET behavior.
* Show when no suspicious thread is linked to a region.
* Show when no YARA match exists.
* Show when network activity is expected for the application type.
* Present both supporting and contradicting evidence.
* Never automatically dismiss a finding solely because of one benign indicator.

### 23. Evidence graph

* Display relationships between:

  * processes;
  * parent processes;
  * threads;
  * memory regions;
  * modules;
  * network connections;
  * YARA matches;
  * findings.
* Allow zooming and panning.
* Filter graph node types.
* Highlight high-risk processes.
* Select a node to open its details.
* Distinguish observed relationships from inferred relationships.
* Export graph data as:

  * GraphML;
  * JSON;
  * image where appropriate.

### 24. Timeline view

* Show process creation and exit times.
* Show network activity times where available.
* Show thread and module events where supported.
* Display findings in chronological order.
* Filter timeline by process.
* Separate reliable timestamps from estimated or unavailable timestamps.
* Export timeline data to CSV or JSON.

### 25. Finding details

Each finding page should show:

* finding ID;
* title;
* affected process;
* severity;
* risk score;
* confidence;
* triggered rules;
* observed evidence;
* inferred explanation;
* supporting artifacts;
* counter-evidence;
* benign possibilities;
* source plugins;
* raw provenance;
* limitations;
* analyst notes.

### 26. Provenance inspector

* Allow the investigator to trace a finding back to:

  * rule contribution;
  * normalized artifact;
  * plugin output;
  * raw output row;
  * plugin command;
  * tool version.
* Display original and normalized values.
* Show the extraction timestamp.
* Show whether the relationship was observed or inferred.
* Export provenance data.

### 27. Search and filtering

* Search by:

  * PID;
  * process name;
  * IP address;
  * port;
  * module;
  * YARA rule;
  * artifact ID;
  * finding ID.
* Filter by:

  * severity;
  * confidence;
  * plugin;
  * artifact type;
  * analysis status;
  * process.
* Save useful filters.
* Clear filters easily.
* Export filtered results.

### 28. Investigator notes

* Add notes to cases.
* Add notes to processes.
* Add notes to findings.
* Add notes to artifacts and graph relationships.
* Record author and UTC timestamp.
* Preserve note-edit history.
* Keep analyst notes separate from automatically generated evidence.
* Include selected notes in reports.

### 29. Reporting

Generate an authoritative JSON report containing:

* case metadata;
* evidence metadata;
* pre-analysis hash;
* post-analysis hash;
* integrity result;
* analysis configuration;
* tool versions;
* plugin execution records;
* normalized artifacts;
* findings;
* rule contributions;
* confidence;
* warnings;
* provenance;
* completion status.

Generate an investigator-readable HTML report containing:

* executive summary;
* high-risk findings;
* process overview;
* evidence graph;
* detailed rule explanations;
* supporting evidence;
* benign explanations;
* failed or incomplete stages;
* integrity verification;
* limitations.

### 30. Report redaction

* Create a redacted copy of a report.
* Allow removal or masking of:

  * usernames;
  * file paths;
  * local IP addresses;
  * command-line arguments;
  * sensitive strings;
  * case notes.
* Preserve the original unredacted report.
* Clearly label redacted reports.
* Record the redaction configuration used.

### 31. Export functionality

Support exporting:

* JSON
* HTML
* CSV
* JSONL
* GraphML
* SQLite case database
* analysis logs
* hash manifests
* plugin execution summaries

The MVP only requires JSON and HTML, while the others can be stretch goals.

### 32. Logs and audit trail

* Maintain application logs.
* Maintain worker logs.
* Maintain plugin stderr logs.
* Record important investigator actions.
* Use UTC timestamps.
* Record case creation.
* Record analysis start, cancellation, failure, and completion.
* Record report generation.
* Record configuration changes.
* Avoid logging sensitive memory content unnecessarily.
* Export audit logs.

### 33. Repeatability support

* Record application version.
* Record Python version.
* Record Volatility version.
* Record plugin names and parameters.
* Record rule-set version and hash.
* Record YARA rule hash.
* Record report-template version.
* Record operating-system information.
* Save the full analysis configuration.
* Allow the same analysis to be repeated.
* Compare repeated outputs for substantive differences.

### 34. Case reopening

* Reopen a previously analysed case.
* Display saved artifacts without rerunning Volatility.
* Regenerate reports.
* Re-run correlation rules on existing normalized data.
* Show previous plugin failures.
* Preserve old reports.
* Create a new analysis run record when reprocessing.

### 35. Analysis coverage dashboard

* Show successful plugins.
* Show failed plugins.
* Show skipped plugins.
* Show partially parsed plugins.
* Show unavailable artifact categories.
* Calculate a coverage summary.
* Explain that missing findings may result from incomplete analysis.
* Include coverage status in the report.

### 36. Performance monitoring

* Record total analysis duration.
* Record per-plugin execution duration.
* Record hashing speed.
* Record peak worker memory usage.
* Record artifact counts.
* Display available disk space.
* Warn when output storage may be insufficient.
* Avoid loading complete large outputs into GUI memory.
* Use pagination or virtualized tables.

### 37. Cancellation and recovery

* Cancel a running plugin.
* Cancel the complete analysis.
* Terminate a non-responsive worker.
* Preserve completed results.
* Mark partial results clearly.
* Allow the analysis to restart.
* Avoid corrupting the case database.
* Record the cancellation reason and time.

### 38. Application settings

* Configure default case directory.
* Configure symbol directory.
* Configure log level.
* Configure plugin timeout.
* Configure enabled rules.
* Configure report options.
* Configure portable or installed mode.
* Restore safe default settings.
* Export and import application configuration.

### 39. Portable operation

* Run without requiring Python to be installed.
* Run from an authorized external drive.
* Store outputs in a selected case directory.
* Avoid permanent system changes.
* Avoid requiring administrator privileges for offline image analysis.
* Include bundled dependencies.
* Display the portable build version.
* Verify important application files with checksums.

### 40. Safety controls

* Never alter the source memory image.
* Never execute extracted files or memory content.
* Never automatically contact discovered IP addresses or domains.
* Never run arbitrary user-supplied commands.
* Never use `shell=True`.
* Restrict plugins to an approved list.
* Validate all file and output paths.
* Prevent output from being written over the evidence file.
* Clearly label findings as triage indicators.
* Display legal and authorization notices.

## Recommended MVP functionality

For the first complete version, prioritize:

1. Case creation.
2. Memory-image selection.
3. SHA-256 before and after analysis.
4. Volatility plugin execution.
5. Progress and error display.
6. Raw-output preservation.
7. Artifact normalization.
8. Process explorer.
9. Process tree.
10. Memory-region analysis.
11. Network analysis.
12. YARA integration.
13. Three to five correlation rules.
14. Explainable process risk scores.
15. Finding details with provenance.
16. Basic evidence graph.
17. JSON report.
18. HTML report.
19. Logs and analysis status.
20. Portable PyInstaller packaging.

## Strong stretch features

* Differential comparison between two memory images.
* Rule-weight simulation.
* Counter-evidence engine.
* Confidence and completeness scoring.
* MITRE ATT&CK hypothesis mapping.
* Timeline visualization.
* Report redaction.
* GraphML and CSV export.
* Linux artifact support.
* Rule regression comparison.
