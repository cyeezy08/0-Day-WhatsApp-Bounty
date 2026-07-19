# WhatsApp Android v2.26.28.71 — Security Audit & Exploit Suite
## Bounty Target: `com.whatsapp` (Analyzed via `syfe.apk` / `WhatsApp.apk`)

This repository contains the findings, decompiled Smali source files, custom extraction tools, exploit scripts, and media fuzzers developed during a comprehensive security audit of WhatsApp's Android Client (version v2.26.28.71). 

---

## 1. Executive Summary & Overview
The security audit revealed **6 distinct security findings** ranging from critical cryptographic validation bypasses to permissionless broadcast receivers and native RCE attack surfaces:
1. **UPI Payment Signature Bypass (Medium):** The client fails to cryptographically verify signature parameters on incoming UPI deep links, facilitating payment parameter spoofing.
2. **Exported OTP Receivers (Medium):** Broadcast receivers handle OTP verification handshakes without permission checks, opening the application to remote-triggered state pollution and background Denial-of-Service (DoS).
3. **WebView Allowlist Subdomain Bypass (Medium):** The host verification pattern uses insecure substring checking (`endsWith`), which allows an attacker who achieves a subdomain takeover on `*.whatsapp.com` to host phishing interfaces within WhatsApp's trusted UI context.
4. **QuickSends Nonce Replay Risk (Low-Medium):** The ContentProvider does not invalidate nonces locally after validation, allowing for potential data replay if a whitelisted Meta application is compromised.
5. **Native Media Parser RCE Surface (Unknown):** Custom media decoders for GIF, WebP, and MP4 are packaged inside the app, exposing the sandbox to potential zero-click RCE.
6. **Exported Services without Permissions (Low):** Multiple internal background services are exported without permission checks, permitting other local applications to invoke them.

---

## 2. The Native Library Red Herring (The "Failed Decision")
One of the key technical learning points during this audit was a structural misconception regarding the native libraries layout.

### The Misconception
Upon inspecting the APK, the team found a massive **13.1 MB** native library at `lib/arm64-v8a/libs.so`. Given its size and string references to `libgifimage.so`, `libstatic-webp.so`, and `libwa_sandboxed_gifimage.so`, the team initially assumed `libs.so` was a monolithic library containing the implementations of all the media parsing components. 

The initial **failed decision** was to load the 13.1 MB `libs.so` file directly into Ghidra to analyze the media parsers. 

### The Discovery
Disassembly and analysis in Ghidra (captured in `analysis/results/ghidra_kali_results.txt`) debunked this approach:
* **Empty Shell:** Despite being 13.1 MB in size, the binary contains only **10 functions** (mostly related to standard JNI lifecycles, global exits, and initialization wrappers such as `__cxa_finalize` and `atexit`).
* **Archive References:** The binary exposed symbols like `_superpack_archive_start`, `_superpack_archive_end`, and `_superpack_archive_size`.
* **Packaging:** `libs.so` was not a compiled parser library. It was an uncompressed **Meta Superpack archive container**. The actual media parsers were compressed and packaged inside this archive payload wrapper.

### The Pivot
To perform native audits on the actual GIF, WebP, and MP4 decoders, the team had to pivot away from disassembling `libs.so` directly. We developed a series of extraction utilities to reconstruct the archive format:
* [extract_superpack.py](file:///home/kali/2stage/analysis/extract_superpack.py): Extracts the raw archive binary payload from the symbol offsets.
* [parse_archive.py](file:///home/kali/2stage/analysis/parse_archive.py) / [parse_archive2.py](file:///home/kali/2stage/analysis/parse_archive2.py): Deciphers the stream headers and compression checkpoints.
* [parse_ob_archive.py](file:///home/kali/2stage/analysis/parse_ob_archive.py): Reconstructs the Openbox container and decompresses individual `.so` files using `zstd`/`zlib`.

This extraction workflow successfully recovered the target binaries, which were saved to `findings/native_analysis/decompressed/`:
* `libgifimage.so` (44 KB) — Main GIF parser.
* `libwa_sandboxed_gifimage.so` (84 KB) — Sandboxed GIF parser.
* `libstatic-webp.so` (43 KB) — WebP parser.
* `libwebpencoder-native.so` (21 KB) — WebP encoder.
* `libwhatsapp.so` (13.1 MB) / `libwhatsappmerged.so` (6.8 MB).

---

## 3. How I Decompiled It — Step-by-Step Guide
To analyze WhatsApp's massive application footprint, we followed a multi-stage decompilation and disassembly pipeline:

### A. Manifest and Resource Unpacking
To inspect the application's components, permissions, and exported interfaces, we unpacked the APK's XML structures and layout files:
```bash
# Extract the manifest and raw resource structures without compiling classes
apktool d WhatsApp.apk -o ws_apktool --no-src
```
This output the readable `AndroidManifest.xml` (located under [whatsapp_manifest.xml](file:///home/kali/2stage/findings/whatsapp_manifest.xml)), allowing us to identify the permissions configurations and locate unprotected receivers or services.

### B. High-Level Java Decompilation
To analyze the application logic in readable Java syntax rather than raw bytecode, we decompiled the classes using JADX. Because the APK contains **11 DEX files** (`classes.dex` through `classes11.dex`), JADX was critical for merging these pools:
```bash
# Decompile the APK to a structured Java source tree
jadx -d ws_output WhatsApp.apk
```
This decompiled all DEX archives, storing Java classes under `ws_output/sources/` and resources under `ws_output/resources/`.

### C. Low-Level Smali Disassembly
While Java decompilation is useful for tracking general control flows, JADX can often struggle with compiler optimizations, generating pseudo-code or missing blocks. For precise bytecode audits (identifying register transfers and method invocations), we disassembled the DEX payload using Baksmali:
```bash
# Disassemble the DEX code to Smali bytecode files
baksmali d WhatsApp.apk -o ws_smali
```
Using the resulting smali codebase (over 90,000 files), we isolated class bytecode files for critical components (such as [C7m.smali](file:///home/kali/2stage/findings/native_analysis/C7m.smali) and [C77.smali](file:///home/kali/2stage/findings/native_analysis/C77.smali)) to trace parameters and confirm bypasses.

---

## 4. Vulnerability Findings Dashboard

| ID | Finding Title | Severity | Status | Target Component | Core Security Risk |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **01** | [UPI Signature Bypass](findings/reports/01_UPI_SIGNATURE_BYPASS.md) | **MEDIUM** | Confirmed | `IndiaUpiPayIntentReceiverActivity` | Phishing / Spoofed Payee and Amount confirmation screens |
| **02** | [Exported OTP Receivers](findings/reports/02_OTP_RECEIVER_EXPLOIT.md) | **MEDIUM** | Confirmed | `OtpRequestedReceiver` | Memory exhaustion, background DoS, state pollution |
| **03** | [WebView Allowlist Bypass](findings/reports/03_WEBVIEW_BYPASS.md) | **MEDIUM** | Confirmed | `WaInAppBrowsingActivity` | In-app phishing context via subdomain takeover |
| **04** | [QuickSends Nonce Replay](findings/reports/04_QUICKSENDS_NONCE.md) | **LOW-MED** | Confirmed | `QuickSendsContactsProvider` | Inter-app data harvesting via compromised whitelisted app |
| **05** | [Native Parser RCE Surface](findings/reports/05_NATIVE_LIBRARIES.md) | **UNKNOWN** | Under Audit | `libgifimage.so` / `libstatic-webp.so` | Zero-click RCE via malformed media streams in chat |
| **06** | [Exported Services](findings/reports/06_EXPORTED_SERVICES.md) | **LOW** | Confirmed | Multiple (e.g., `BackupNowService`) | Unauthorized background tasks triggerable by any local app |

---

## 5. Vulnerability Summaries

### Finding 1: UPI Payment Signature Bypass
* **Component:** `IndiaUpiPayIntentReceiverActivity.smali` -> `C7m.smali` (Parser) & `C77.smali` (Validator)
* **Description:** Incoming UPI deep links (`upi://pay`) parse the `sign` query parameter but do not verify its cryptographic validity. 
* **Exploit Vector:** An attacker can launch a spoofed payment screen with custom amounts and fake payee names (e.g., "Amazon Shopping"):
  ```bash
  adb shell am start -a android.intent.action.VIEW \
    -d "upi://pay?pa=attacker@upi&pn=Amazon+Shopping&am=50000&cu=INR&tn=Refund+Claim&sign=fakesignature123"
  ```
* **Mitigating Factors:** Tapping "Pay" and entering the UPI PIN still requires manual user verification.

### Finding 2: Exported OTP Receivers
* **Component:** `OtpRequestedReceiver.smali` & `OtpIdentityHashRequestedReceiver.smali`
* **Description:** WhatsApp exports its OTP handshake broadcast receivers without permission guards. When an external intent containing a spoofed package identifier is received, WhatsApp immediately generates a UUID token and puts it into an in-memory `ConcurrentHashMap` singleton before checking if the sender is whitelisted.
* **Impact:** State pollution and resource exhaustion (DoS) via endless broadcast flows.

### Finding 3: WebView Allowlist Subdomain Bypass
* **Component:** `WaInAppBrowsingActivity.smali` -> `LX/8Cz.smali` (Host Matcher)
* **Description:** The URL validator checks subdomains using `host.endsWith("." + allowedHost)` rather than strict domain checks. 
* **Impact:** If an attacker identifies a dangling DNS record on a subdomain (e.g., `promo.whatsapp.com`), they can point it to their server. The in-app webview will validate and load the attacker's server, mimicking WhatsApp secure contexts.

### Finding 4: QuickSends Contacts Provider Nonce Replay
* **Component:** `QuickSendsContactsProvider.smali`
* **Description:** Exposes contact records (`obfuscated_chat_id`, `display_name`) to whitelisted Meta apps. The provider checks a server-side nonce via the Waffle API but fails to consume it locally.
* **Impact:** Allows an attacker who has hijacked a whitelisted application (like Facebook or Instagram) to execute content queries multiple times using the same nonce.

---

## 6. Disclosure Decisions & Strategy
Every finding was evaluated against WhatsApp's HackerOne Bug Bounty Program guidelines to determine reportability, assess business/safety impacts, and prioritize submissions:

* **Finding 1: UPI Payment Signature Bypass (MEDIUM) ➔ Report Immediately**
  * *Decision:* Submitted.
  * *Rationale:* The bug violates UPI's cryptographic sign validation mandates. Allowing attackers to arbitrarily forge payment metadata (payee name and amount) on the official checkout screen makes it a high-utility phishing vector.
* **Finding 2: Exported OTP Receivers (MEDIUM) ➔ Report Immediately**
  * *Decision:* Submitted.
  * *Rationale:* Permissionless broadcast receivers are a direct entry point. While actual confirmation broadcasts depend on features/configs, the memory allocations occur unconditionally, allowing background state pollution and system memory pressure attacks.
* **Finding 3: WebView Subdomain Allowlist Bypass (MEDIUM) ➔ Report Immediately**
  * *Decision:* Submitted.
  * *Rationale:* Subdomain takeovers on Meta properties occur occasionally. Bypassing host validation via substring matching permits loading third-party content directly within WhatsApp's trusted UI, causing severe phishing risk.
* **Finding 4: QuickSends Nonce Replay (LOW-MEDIUM) ➔ Report as Informative / Defense-in-Depth**
  * *Decision:* Submitted.
  * *Rationale:* While this represents a clear cryptographic flaw (nonces should be single-use), exploitation requires a pre-existing vulnerability or compromise inside a whitelisted Meta app (Facebook/Instagram). Lower priority, but submitted to ensure code remediation.
* **Finding 5: Native Media Parser RCE Surface (UNKNOWN) ➔ Hold Disclosure (Active Audit)**
  * *Decision:* **DO NOT DISCLOSE YET**.
  * *Rationale:* Presenting vulnerabilities in dependencies or media parser libraries without a verifiable crash, memory corruption proof (e.g. ASAN logs), or an operational exploit chain will result in a quick rejection as "theoretical." We must continue Ghidra analysis and fuzzing on the extracted `.so` targets to find an active exploit vector first.
* **Finding 6: Exported Services without Permissions (LOW) ➔ Retain Internally (Document Only)**
  * *Decision:* Exclude from disclosure reports.
  * *Rationale:* Exported services without permission guards are generally considered "Informative" or "Out of Scope" on HackerOne unless chained with a "Confused Deputy" vulnerability showing direct privilege escalation.

---

## 7. Exploit Development & Fuzzing Harnesses
The codebase includes PoCs and automation scripts to test and demonstrate the vulnerabilities:

### OTP Exploit Suite (`exploit/`)
* **[SETUP.sh](file:///home/kali/2stage/exploit/SETUP.sh):** Verifies the emulator or physical device connections, installs dependencies, validates WhatsApp, pushes Frida tools, and checks receiver availability.
* **[otp_exploit_frida.js](file:///home/kali/2stage/exploit/otp_exploit_frida.js):** Dynamic hooking script to inject spoofed `PendingIntent` references into WhatsApp's live memory.
* **[OtpExploitActivity.java](file:///home/kali/2stage/exploit/OtpExploitActivity.java):** Java source code for a custom helper application that triggers the OTP handshake lifecycle.
* **[test_otp_adb.sh](file:///home/kali/2stage/exploit/test_otp_adb.sh):** Simplified shell script that tests receiver accessibility directly via ADB.

### Media Parser Fuzzing Suite (`fuzz/`)
* **[generate_crash_gif.py](file:///home/kali/2stage/fuzz/generate_crash_gif.py):** Generates crash test cases, including double-free variants, zero-size frames, nested comments, and WebP massive chunk variations.
* **[surgical_exploit.py](file:///home/kali/2stage/fuzz/surgical_exploit.py) & [real_exploit.py](file:///home/kali/2stage/fuzz/real_exploit.py):** Encodes malformed GIFs where the first frame is valid (to survive sending-side thumbnail generation) but the second frame declares a 1x1 size while supplying massive LZW data (up to 2,500 bytes) to force a heap overflow on the recipient's device.
* **[webp_exploit.py](file:///home/kali/2stage/fuzz/webp_exploit.py):** Builds malformed VP8L (lossless) transforms mimicking historical CVE-2023-4863 patterns.
* **[hook_gif_parser.js](file:///home/kali/2stage/fuzz/hook_gif_parser.js):** Frida instrumentation hook targeting execution flows inside `libgifimage.so` and `libwa_sandboxed_gifimage.so` to track rendering crashes.

---

## 8. Directory Layout
```
/home/kali/2stage/
├── WhatsApp.apk                     ← WhatsApp Target APK (v2.26.28.71)
├── README.md                        ← This documentation guide
├── analysis/                        
│   ├── so_files/                    ← Decompiled native folder structure
│   ├── extracted_libs/              ← Extracted Superpack libraries
│   ├── results/                     ← Symbol dumps & Ghidra parsing outputs
│   │   └── ghidra_kali_results.txt  ← Analysis of libs.so debunking the monolith model
│   ├── extract_superpack.py         ← Superpack payload extractor
│   ├── parse_archive.py             ← Archive format parser
│   └── parse_ob_archive.py          ← Openbox container unpacker
├── findings/                        
│   ├── reports/                     ← Detailed finding markdown documents (01-06)
│   └── native_analysis/             
│       ├── C7m.smali / C77.smali    ← UPI validation smali sources
│       └── decompressed/            ← Extracted media parser libraries (.so files)
├── exploit/                         
│   ├── OtpExploitActivity.java      ← Android helper APK source
│   ├── otp_exploit_frida.js         ← Frida injection payload
│   └── SETUP.sh                     ← Exploit suite installer & verifier
└── fuzz/                            
    ├── crafted_gifs/                ← Generated malformed media payloads
    ├── generate_crash_gif.py        ← Crash test case generator
    ├── surgical_exploit.py          ← Multi-frame heap overflow GIF generator
    └── hook_gif_parser.js           ← Frida hook for native media parser tracking
```
