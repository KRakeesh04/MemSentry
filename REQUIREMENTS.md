# MemSentry — Requirements

## 1. Main Goal

Build a **desktop application** that helps investigators analyze RAM dumps without having to manually run many Volatility commands.

The basic process is:

**Create Case → Add RAM Dump → Verify File → Run Analysis → Show Results → Detect Suspicious Activity → Generate Report**

---

# 2. Case Management

The system should allow the user to:

* Create a new investigation case.
* Open an existing case.
* Edit case information.
* Store a case name and description.
* Store investigator information.
* Add one or more RAM dumps to a case.
* View previous analyses performed for the case.

---

# 3. RAM Dump / Evidence Management

The system should allow the user to:

* Select a RAM dump from the computer.
* Add the RAM dump to a case.
* Support common memory image formats such as:

  * `.raw`
  * `.mem`
  * `.dmp`
* Store the file name, path and size.
* Store available information about the source operating system.
* Keep the original RAM dump unchanged.

---

# 4. Evidence Integrity

When a RAM dump is added:

* Calculate its **SHA-256 hash**.
* Store the hash in the database.
* Allow the hash to be calculated again later.
* Compare the new hash with the original hash.
* Warn the user if the hashes do not match.

This helps prove that the evidence has not been modified.

---

# 5. Operating System / Memory Image Detection

The system should try to identify information about the RAM dump such as:

* Windows, Linux or macOS.
* Operating system version/build when available.
* System architecture when available.
* Kernel information when available.
* Required Volatility symbols.

If the required information cannot be detected, show a clear error or warning to the user.

---

# 6. Volatility Integration

Use **Volatility 3** as the main memory analysis engine.

The application should:

* Connect to/use Volatility from the application.
* Give Volatility the selected RAM dump.
* Execute Volatility plugins.
* Capture plugin results.
* Capture Volatility errors.
* Convert useful results into a format that the application can display.

The user should not need to manually type Volatility commands.

---

# 7. Plugin Management

The application should:

* Get the available plugins from Volatility.
* Display available plugins to the user.
* Group plugins by operating system where possible.
* Allow users to enable plugins.
* Allow users to disable plugins.
* Show basic information about each plugin.
* Check whether a plugin can run before execution where possible.

Example plugins may include:

* `pslist`
* `pstree`
* `psscan`
* `cmdline`
* `dlllist`
* `handles`
* `netscan`
* `malfind`

The available plugins will depend on the operating system and Volatility version.

---

# 8. Analysis

The user should be able to:

* Select a RAM dump.
* Select the plugins to run.
* Start analysis.
* Cancel analysis where possible.
* See analysis progress.
* See which plugin is currently running.

Possible plugin states:

* Pending
* Running
* Completed
* Failed

If one plugin fails, the application should record the error and continue running other independent plugins where possible.

---

# 9. Process Analysis

The application should extract useful process information such as:

* Process name
* PID
* Parent PID
* Process start time
* Process exit time where available
* Command-line arguments
* Process relationships

The application should also provide a **process tree** where possible.

Example:

```text
explorer.exe
   |
   +-- powershell.exe
          |
          +-- suspicious.exe
```

---

# 10. Network Analysis

Where supported by the memory image and plugin, show:

* Local IP address
* Remote IP address
* Local port
* Remote port
* Connection state
* Related process
* PID

This helps investigators connect network activity with processes.

---

# 11. Suspicious Activity Detection

The application should help identify potentially suspicious artifacts.

Examples:

* Suspicious process names.
* Strange parent-child process relationships.
* Suspicious command-line arguments.
* Processes running from unusual locations.
* Possible injected code.
* Hidden or inconsistent processes.
* Suspicious network connections.

The application should mark these as **potential indicators**, not automatically claim that they are malware.

---

# 12. Correlation

Combine results from different plugins to provide more useful information.

For example:

```text
Process
   ↓
Command Line
   ↓
Network Connection
   ↓
Loaded DLL
   ↓
Suspicious Memory Region
```

Example finding:

```text
Process: powershell.exe
PID: 3456

Command:
powershell.exe -enc ...

Network:
192.168.1.20 → External IP

Detection:
Suspicious encoded PowerShell command

Risk:
HIGH
```

This allows the investigator to understand the activity without checking every plugin result separately.

---

# 13. Findings

Important or suspicious results should be stored as **findings**.

A finding can contain:

* Finding name.
* Description.
* Related process.
* Related artifacts.
* Plugin that discovered the information.
* Detection rule.
* Severity.

Example severity levels:

* Informational
* Low
* Medium
* High
* Critical

---

# 14. Dashboard

The main dashboard should show a simple investigation summary.

For example:

* Case information.
* RAM dump information.
* Evidence hash status.
* Operating system.
* Analysis status.
* Plugins executed.
* Number of processes found.
* Network connections found.
* Suspicious findings.
* Failed plugins.
* Important alerts.

---

# 15. Detailed Results

The user should be able to open individual analysis results.

For a process, for example, show:

```text
Process Name: powershell.exe
PID: 3456
PPID: 1024
Started: 10:42:13

Command:
powershell.exe -enc ...

Network Connections:
2

Related Findings:
1 High Severity Finding
```

---

# 16. Search and Filtering

The user should be able to search results using things such as:

* Process name
* PID
* IP address
* Port
* Plugin
* Artifact type
* Severity
* Suspicious/normal status

---

# 17. Database

Use a local database such as **SQLite**.

The database should mainly store:

* Cases
* Evidence information
* Evidence hashes
* Analysis sessions
* Plugin execution information
* Parsed artifacts/results
* Findings
* Application/audit logs

The actual RAM dump should normally remain as a file rather than being stored inside the database.

---

# 18. Logging

The application should keep logs for important actions.

Examples:

* Case created.
* RAM dump added.
* SHA-256 calculated.
* Hash verified.
* Analysis started.
* Plugin started.
* Plugin completed.
* Plugin failed.
* Analysis completed.
* Report generated.

This is important for forensic traceability.

---

# 19. Report Generation

The user should be able to generate a forensic report.

The report should contain:

* Case information.
* Investigator information.
* Evidence information.
* SHA-256 hash.
* Memory image information.
* Analysis date/time.
* Volatility/tool version.
* Plugins executed.
* Plugin failures.
* Important artifacts.
* Suspicious findings.
* Investigator notes where applicable.

---

# 20. Export

Allow users to export results.

Main formats:

* CSV
* JSON

Human-readable reports can additionally be generated as:

* HTML
* PDF

---

# 21. Error Handling

Show understandable errors instead of only displaying raw technical errors.

Handle situations such as:

* RAM dump does not exist.
* RAM dump cannot be read.
* Unsupported memory image.
* Missing Volatility symbols.
* Plugin cannot run.
* Plugin crashes/fails.
* Parsing fails.
* Database error.
* Report generation error.

Technical details can still be saved in logs for debugging.

---

# 22. Security and Forensic Requirements

The application must:

* Never silently modify the original RAM dump.
* Calculate SHA-256 hashes.
* Verify evidence integrity.
* Keep analysis linked to its evidence.
* Keep findings linked to their source results.
* Record important actions.
* Store analysis errors.
* Keep forensic data locally unless the user explicitly exports it.
* Clearly distinguish automated warnings from confirmed investigator conclusions.

---

# 23. Performance Requirements

The application should:

* Handle large RAM dump files.
* Run analysis without freezing the GUI.
* Show progress during long operations.
* Allow independent plugins to continue if another plugin fails.
* Avoid unnecessarily loading an entire RAM image into application memory.

---

# 24. Cross-Platform Requirements

The project should aim to analyze memory images from:

* Windows
* Linux
* macOS

However, available analysis features and plugins may be different for each operating system.

The desktop application itself should also be designed with cross-platform support in mind.

---

# 25. Minimum Features to Build First

For the first working version, focus on:

1. Case management.
2. RAM dump import.
3. SHA-256 hashing.
4. Evidence verification.
5. Volatility integration.
6. Available plugin detection.
7. Plugin enable/disable.
8. Plugin execution.
9. Process analysis.
10. Network analysis where supported.
11. Structured result display.
12. Basic correlation.
13. Basic suspicious activity detection.
14. Dashboard.
15. SQLite database.
16. CSV/JSON export.
17. Report generation.
18. Logging and error handling.

---

# 26. Features to Add Later

After the main application works, consider:

* Live RAM acquisition.
* YARA scanning.
* IOC matching.
* Advanced timeline generation.
* Advanced process-tree visualization.
* Network graphs.
* Custom detection rules.
* More advanced malware detection.
* Comparison between memory images.
* Additional automated correlation.
* Evidence package export.

---

# 27. Simple System Flow

```text
        Investigator
             |
             v
        Create Case
             |
             v
       Add RAM Dump
             |
             v
     Calculate SHA-256
             |
             v
      Verify Evidence
             |
             v
    Identify RAM Image
             |
             v
     Select Plugins
             |
             v
       Volatility 3
             |
             v
      Plugin Results
             |
             v
       Parse Results
             |
             v
   Correlate Artifacts
             |
             v
  Detect Suspicious Activity
             |
             v
    Dashboard / Findings
             |
             v
       Export / Report
```

## Main Rule

Every important finding should be traceable back to where it came from:

**Finding → Artifact → Plugin → Analysis → RAM Dump → SHA-256 → Case**

That is one of the most important requirements for keeping the tool useful for digital forensic investigations.
