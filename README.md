ConvertMate / UpdateRetreiver — Static Malware Analysis
Static reverse engineering | Windows/.NET | October 26, 2026

This repository documents a forensic investigation into the ConvertMate installer and its bundled UpdateRetreiver.exe updater in an incident with confirmed MediaArena malware, including installation behavior, scheduled-task persistence, encrypted network retrieval, and in-memory .NET assembly loading.
[!IMPORTANT]
MediaArena was confirmed in the investigated incident (analyst-confirmed). This README examines ConvertMate and its updater in that incident context. The static reverse engineering establishes an encrypted remote .NET loading mechanism, but does not by itself prove that this specific mechanism delivered or executed the confirmed MediaArena payload.

Executive summary
The examined ConvertMate installer includes a bundled Windows application, a PowerShell task-registration script, and updater components. Decompiled updater code reveals a remotely supplied .NET assembly loading mechanism:
- Installation: Extracts Native.zip to %LOCALAPPDATA%\ConvertMate and launches Convert Mate.exe in the observed installation flow.
- Persistence capability: The embedded conmate_update.ps1 script registers a daily Windows scheduled task named ConvertMateTask, targeting UpdateRetreiver.exe.
- Remote retrieval: The updater obtains a token from confetly.com/auth, then requests data from confetly.com/update with a bearer token and time-based headers.
- Decryption: The updater uses AES with a SHA-256-derived key and MD5-derived IV based on timestamps, then parses the decrypted response as a collection of byte arrays.
- In-process loading: The updater calls AppDomain.Load(byte[]) and reflectively invokes a loaded assembly's entry point.
These are code-level observations, not proof that a scheduled task successfully ran, that the remote service returned a payload, or that a particular malware family was executed.
Observed execution chain
ConvertMate.exe (.NET installer)
  |
  +-- Native.zip ------------------> %LOCALAPPDATA%\ConvertMate\Convert Mate.exe
  |
  +-- conmate_update.ps1 ----------> ConvertMateTask (daily scheduled task)
  |                                   |
  +-- Updating_files.zip               +--> UpdateRetreiver.exe
                                            |
                                            +--> Read id.txt and creation timestamp
                                            +--> GET /auth (retrieve token)
                                            +--> GET /update (encrypted response)
                                            +--> AES decrypt
                                            +--> JSON -> IEnumerable<byte[]>
                                            +--> AppDomain.Load(byte[])
                                            +--> EntryPoint.Invoke(...)
Execution-chain caveat: The report establishes the components and their code-level relationships, but does not identify every ZIP extraction call site or demonstrate successful task registration and runtime execution on an affected endpoint.
Key findings
Finding	Evidence	Assessment
Embedded installer resources	Native.zip, Updating_files.zip, conmate_update.ps1	Confirmed in extracted resources
Per-install identifier	id.txt stores a generated/reused GUID	Confirmed in code
Scheduled-task registration	PowerShell COM registration of ConvertMateTask, daily trigger	Confirmed script capability; endpoint success not confirmed
Authenticated update request	/auth, bearer-protected /update	Confirmed in decompiled code; traffic not captured
Encrypted response processing	AES decrypt and JSON deserialization to byte arrays	Confirmed in code
Managed assembly execution mechanism	AppDomain.Load(raw) and EntryPoint.Invoke()	Confirmed in code; actual payload execution not shown
MediaArena incident finding	Analyst confirms MediaArena in the investigated incident; confirming detection artifacts are not reproduced in the source report	Confirmed incident finding (analyst-provided); precise delivery route not independently established here


SHA-256 indicators
The following values were transcribed from the analyst's terminal output. They have not been independently rehashed against binaries included with this README.
Artifact	SHA-256
ConvertMate.exe (original)	08b9f93000512b45f8c2e8d3d6624536b366e67c40fd4b958db58e3a1d129c3d
Convert Mate.exe (inside Native.zip)	d9f9584f4f071be9c5cf418cae91423c51d53ecf9924ed39b42028d1314a2edc
UpdateRetreiver.exe (inside Updating_files.zip)	09c2af472ab86b62a702e94a39df2bef09205f4249ed871cbeece751c1e7ef4f


The original report also records hashes for exported resources including Native.zip, Updating_files.zip, Uninstall.zip, favicon.ico, and conmate_update.ps1.
Network indicators (static)
Do not browse to these addresses from an ordinary workstation. These endpoints were observed in source code; successful connections and malicious hosting have not been independently verified.
Indicator (defanged)	Observed use
banifuri[.]com/get-known-values	Installer configuration
banifuri[.]com/log	Installer logging
banifuri[.]com/pixel	Installer tracking/pixel request
confetly[.]com/auth	Updater authentication/token request
confetly[.]com/update	Encrypted update retrieval
confetly[.]com/iserr	Updater error reporting
confetly[.]com/is5m	Updater MD5/reporting callback
chrialletworton[.]com/524c5f6f-7ad4-4468-a535-e7598d5af5a3	URL passed to process launch arguments; surrounding call site needs further analysis


Persistence details
Recovered conmate_update.ps1 configures:
- Task name: ConvertMateTask
- Program: %LOCALAPPDATA%\ConvertMate\UpdateRetreiver.exe
- Trigger: Daily, with initial start boundary computed as approximately 24 hours after registration
- Network: Runs only when network is available
- Recovery: Up to two restarts after failure, at 10-minute intervals
- Account: Current domain/user context specified by the script
The installer attempts to invoke the exported PowerShell script and subsequently deletes the script file. Registration is conditional in the observed installer code. Task creation on a real host is not proven by static analysis alone.
Encrypted update and assembly loading
Relevant decompiled logic, abbreviated for readability:
using Aes aes = Aes.Create();
aes.Key = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(installDate));
aes.IV = MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(currentDate));

// Decrypt remote response, then parse as a collection of byte arrays.
IEnumerable<byte[]> assemblies =
    JsonConvert.DeserializeObject<IEnumerable<byte[]>>(decryptedResponse);

// For each non-empty assembly byte array:
Assembly loaded = AppDomain.CurrentDomain.Load(raw);
MethodInfo entryPoint = loaded.EntryPoint;
entryPoint?.Invoke(null, new object[] { arguments });
The key and IV derive from timestamp text, not from independently generated secret key material. The report does not contain captured ciphertext, decrypted server responses, or a remotely delivered assembly. This snippet is illustrative and not a complete compilable reproduction.
MITRE ATT&CK mapping (provisional)
Technique	Observed basis
T1053.005 — Scheduled Task/Job: Scheduled Task	Task-registration script
T1620 — Reflective Code Loading	AppDomain.Load(byte[]) and entry-point invocation
T1140 — Deobfuscate/Decode Files or Information	AES decryption of remote content
T1071.001 — Application Layer Protocol: Web Protocols	HTTP(S) authentication, update, and reporting code
T1027 — Obfuscated Files or Information	Reversed strings and fragmented identifiers


Mappings describe observed capabilities, not proof of adversary identity or actual execution. Validate technique mapping against the ATT&CK version used by your organization.
Defensive hunting examples (Microsoft Defender XDR)
Process discovery
DeviceProcessEvents
| where FileName in~ ("ConvertMate.exe", "Convert Mate.exe", "UpdateRetreiver.exe")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
Network discovery
DeviceNetworkEvents
| where RemoteUrl has_any ("confetly.com", "banifuri.com")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessSHA256, RemoteUrl, RemoteIP, ActionType
| order by Timestamp desc
Hash-based file discovery
DeviceFileEvents
| where SHA256 in~ (
    "08b9f93000512b45f8c2e8d3d6624536b366e67c40fd4b958db58e3a1d129c3d",
    "d9f9584f4f071be9c5cf418cae91423c51d53ecf9924ed39b42028d1314a2edc",
    "09c2af472ab86b62a702e94a39df2bef09205f4249ed871cbeece751c1e7ef4f"
)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
| order by Timestamp desc
These queries are starting points. Data availability and retention vary, and an in-memory assembly may not produce a corresponding file-creation event.
Tools and methodology
- Ghidra: Initial examination of the Windows PE/.NET installer
- ILSpy CLI 11.1.0.9782: Managed-code decompilation and inspection
- .NET SDK 10.0.403 on Kali Linux: ILSpy execution environment
- unzip, sha256sum, shell utilities: Archive inspection, extraction, and evidence inventory
The documented workflow consisted of static analysis and extraction. The report does not establish that the suspect executable was run during the Kali analysis.
Unresolved technical questions
- Which specific file, hash, process, and detection event document the confirmed MediaArena finding?
- Did ConvertMateTask actually register and run on the affected endpoint?
- What did the remote update endpoint return, if anything?
- Was a managed assembly loaded and executed at runtime?
- Did Convert Mate.exe, the affiliate installation flow, or an unrelated source account for the suspected detection?
Additional evidence required includes original Defender alert metadata, endpoint process trees, task history/XML, network telemetry, updater memory or EDR assembly-load evidence, and independent hash verification.
Full investigation report
See ConvertMate_MediaArena_Forensic_Analysis_Report.docx for the extended forensic analysis, code excerpts, evidence inventory, source anchors, and investigation limitations. Add the report to the repository under that filename (or update this link to match the file you commit).
Safety and disclosure
This material is intended for defensive security research, incident response, and threat hunting. Treat all samples and infrastructure indicators as potentially unsafe. Do not execute unknown binaries or connect to the listed infrastructure outside an authorized, isolated research environment.

