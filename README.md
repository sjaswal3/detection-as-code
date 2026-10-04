# Detection-as-Code Pipeline

Sigma detection rules that are automatically tested against real Windows attack logs on every push, using GitHub Actions and Chainsaw.

## How it works
1. Each rule in `rules/` is paired with a real attack log in `tests.yml` (from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)).
2. On every push, GitHub Actions runs each rule against its log with [Chainsaw](https://github.com/WithSecureOpenSource/chainsaw).
3. If a rule stops catching its attack, the build fails.

## Detection coverage
| Rule | ATT&CK | Attack log | Result |
|---|---|---|---|
| Suspicious Access to LSASS Memory | T1003.001 | Mimikatz sekurlsa::logonpasswords | ✅ Caught |
| DCSync Directory Replication Request | T1003.006 | Mimikatz lsadump::dcsync | ✅ Caught |
| PowerShell LSASS Dump via MiniDumpWriteDump | T1003.001, T1059.001 | PowerShell script block (4104) | ✅ Caught |
| Memory Dump via comsvcs.dll MiniDump | T1003.001, T1218.011 | rundll32 living-off-the-land dump | ✅ Caught |
