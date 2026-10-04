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
