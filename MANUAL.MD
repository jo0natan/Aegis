# Aegis Codex Engine — Comprehensive Operations Manual
### `Jonatan Villela - jonatan.villela@gmail.com` <!-- --- ``` Custos vigilans, mundum munit ``` --- -->

---

## 1. Executive Architecture Overview

The **Aegis Codex Engine** (`Aegis_console.js`) is an elite, standalone JavaScript runtime hardening and anti-inspection framework designed for Senior Security Analysts and Vulnerability Researchers. Engineered to be injected directly into hostile, highly-monitored browser environments (such as commercial web applications embedded with aggressive Real User Monitoring like Datadog RUM), the engine enforces the **CIA Triad** and **Defense-in-Depth** directly inside the client-side V8/Chromium execution thread.

When paired with a hardened host platform like **GrapheneOS** running on a Google Pixel with a locked bootloader via custom keys, the Aegis Codex Engine establishes an ironclad, auditable sandbox. It strips third-party scripts of their ability to exfiltrate telemetry, detect automation, or profiles user interactions, guaranteeing absolute digital sovereignty.

```
+-----------------------------------------------------------------------+
|                       CLIENT BROWSER RUNTIME                          |
|                                                                       |
|   +--------------------------+         +--------------------------+   |
|   |    HOSTILE APPLICATION   |         |    TELEMETRY ENGINES     |   |
|   |   (e.g., Hostile)        |         |   (e.g.,artifact RUM)    |   |
|   +------------+-------------+         +------------+-------------+   |
|                |                                    |                 |
|                v                                    v                 |
|     ============================================================      |
|     ||                 AEGIS CODEX FIREWALL WALL              ||      |
|     ============================================================      |
|                |                                    |                 |
|                | Intercepted                        | Dropped/Spoofed |
|                v                                    v                 |
|   +--------------------------+         +--------------------------+   |
|   |  AegisMemoryPurgeCore    |         |   Biometric Spoof Proxy  |   |
|   |  (Recursive Node Purge)  |         |   (isTrusted Reflection) |   |
|   +--------------------------+         +--------------------------+   |
+-----------------------------------------------------------------------+
```

---

## 2. Core Subsystems & Technical Specifications

### A. Memory Hardening & Garbage Collection Core (`AegisMemoryPurgeCore`)
Invasive modern web applications weaponize structural floods—spawning millions of state changes—to trigger high-latency overloads or identify automation frameworks. This behavior creates massive cascades of **Detached DOM Nodes (Ghost Nodes)** that remain bound to volatile heap memory through hidden closures or lingering framework references, rapidly degrading device performance.

`AegisMemoryPurgeCore` counters this via an aggressive **Recursive Node Nullification** algorithm:
1. **Tree Scanning:** Utilizes a highly optimized native `TreeWalker` instance to scan and capture all operational nodes currently severed from the active root document tree structure (`!document.documentElement.contains(currentNode)`).
2. **Atomic Disconnection:** Invokes `cloneNode(true)` on targeted elements to surgically strip away all attached anonymous event listeners, rendering the residual node functionally inert.
3. **V8 Property Shredding:** Loops through all physical and hidden property keys belonging to the node using `Object.getOwnPropertyNames()`, explicitly reassigning every internal variable slot to `null`. This forcefully unlinks circular memory structures, forcing the V8 engine's Garbage Collector to release memory segments instantly.

### B. DOM Mutation Firewall
The core engine intercepts native Chromium node manipulation vectors (`Node.prototype.appendChild`, `removeChild`, `insertBefore`, and `replaceChild`) via robust method hook wrappers (Monkey Patching). 
* **Dynamic Whitelisting:** Every transaction is verified against a secure selector layout (`allowSelectors: ['#app', '[data-safe]']`). If an unmapped tracker attempts to alter or inject elements, the operation is blocked.
* **Resilient Graceful Fallbacks:** To prevent application crashes when a script attempts to remove an already hidden or isolated element, the firewall handles parent-child synchronization issues seamlessly, isolating the script's visibility without throwing fatal runtime errors.
* **Auto-Purge Threshold:** Tracks global collision counts. Upon reaching the configured burst limit (e.g., `autoPurgeMutationThreshold: 50000`), the engine triggers a comprehensive memory flush via `AegisMemoryPurgeCore`, neutralizing memory-exhaustion tactics on the fly.

### C. Advanced XHR Sniffer & Network Control
The engine intercepts native network bindings (`XMLHttpRequest.prototype.open` and `proto.send`) to create real-time, auditable interception pipelines.
* **Context Preservation:** Attaches a transient metadata object (`_codexContext`) directly to the active XHR instance, tracking the underlying HTTP method, complete URL pathing, and timestamps.
* **Leak Prevention Lifecycle:** Response payloads are safely monitored and truncated based on maximum safe-length allowances (`truncateResponseLen: 200`). To block tracking engines from sniffing internal data trails, the contextual tracking wrapper is completely destroyed within a strict `finally` execution block at the end of the request lifecycle.

### D. Biometric & Automation Evasion Layer
To circumvent fingerprinting metrics that probe for behavioral characteristics or devtools instrumentation, Aegis deploys complex JavaScript Proxies that forge perfect human-like interactions:
* **`isTrusted` Proxy Forgery:** Intercepts security checks querying the native read-only `Event.prototype.isTrusted` flag.
* **Reflection Evasion:** Overrides standard reflection traps including `getOwnPropertyDescriptor`, `hasOwnProperty`, `getPrototypeOf`, and `toString`. If telemetry engines attempt to inspect whether `isTrusted` has been modified, the proxy fakes a native ecosystem response, reporting the event as pristine and authentic.
* **Humanized Cursor Kinematics:** Simulates physical interaction telemetry using randomized mathematical smoothing algorithms (*Linear Interpolation/LERP*, *Ease-InOut* functions, and macro *Jitter*), creating natural behavioral data that bypasses AI-driven anomaly detectors.

---

## 3. Configuration & Parameter Matrix

The global operational profile of `AegisCodexEngine` can be fully tuned through its internal configuration schema. Below is the technical specification of the parameters mapped directly from the engine's core code:

| Category | Parameter Key | Default Value | Technical Description |
| :--- | :--- | :--- | :--- |
| **`policy`** | `allowSelectors` | `['#app', '[data-safe]']` | Array of structural DOM selectors permitted to mutate the active tree layout. |
| | `logMutations` | `true` | Toggles immediate auditing of caught mutation attempts within the active console view. |
| | `revertMutations` | `true` | Enforcement flag that actively reverts unauthorized changes made to protected layouts. |
| | `freezeConsole` | `true` | Prevents malicious scripts from overriding or clearing console outputs to hide execution traces. |
| **`keepAlive`** | `wakeLockScreen` | `true` | Requests hardware screen-saver blocks to maintain uninterrupted engine background execution. |
| | `silentAudioInterval` | `500` (ms) | Frequency for generating empty micro-audio buffers to bypass background execution throttling. |
| | `aggressiveTickInterval`| `100` (ms) | Operational frequency of the main engine internal heartbeat loop. |
| | `driftThreshold` | `200` (ms) | Detection ceiling for internal clock skew, identifying if the execution host is freezing or debugging. |
| **`network`** | `monitorXHR` | `true` | Globally toggles active network sniffer instrumentation across the active execution space. |
| | `truncateResponseLen`| `200` (chars) | Structural character restriction threshold for payload logging to mitigate memory overhead. |
| **`memory`** | `purgeOnMutationBurst`| `true` | Auto-purges heap data whenever massive script mutation floods are detected. |
| | `autoPurgeMutationThreshold`| `50000` | Minimum sequential collision block limit that triggers automated memory reclamation. |
| | `exposeEnabledToolsAlias`| `true` | Automatically provisions direct terminal shortcut linkages into global namespace layouts. |

---

## 4. Operational Manual: Interactive Terminal Commands

The closing layer of the engine injects a stylized command console abstraction interface directly into `globalThis`, turning the browser's developer console into a dedicated secure command-line interface.

Analysts can interact with the engine using the following built-in command vectors:

### 📑 `AegisManual.help(topic)` / `AegisManual.manual(topic)`
Outputs interactive reference documentation guides straight into the console.
* **Usage:** `AegisManual.help('all')` or specify individual topics: `'policy'`, `'keepAlive'`, `'network'`, `'memory'`, `'evasion'`.

### 🔍 `AegisManual.list()`
Returns a clean, programmatically accessibly list of all registered help topics available within the loaded build profile.

### 📊 `AegisManual.status()`
Generates an on-demand, high-fidelity security diagnostic report detailing the real-time operational status of the framework.

```
+-------------------------------------------------------------+
|               AEGIS SYSTEMS OPERATIONAL REPORT              |
+-------------------------------------------------------------+
|  [PROCESS ID]  : AEGIS-EVADE-84920                          |
|  [BOOTSTRAP]   : SUCCESSFUL (Runtime Mode Engaged)          |
|  [MUTATIONS]   : 142,391 Blocked | 3 Auto-Purge Cycles      |
|  [XHR SNIFFER] : ACTIVE (14 Intercepted Sockets)            |
|  [KEEP-ALIVE]  : TICK SYNC STABLE                           |
+-------------------------------------------------------------+
```

### 🧹 `AegisManual.purge()`
Manually forces an immediate, aggressive memory reclamation cycle across the entire window scope, shredding all unlinked objects and detached node trees.

---

## 5. Security Doctrine Validation

By maintaining an architecture that completely decouples the application runtime from host mechanics, the **Aegis Codex Engine** successfully enforces an un-breachable defensive barrier:

* **Confidentiality:** Hostile scripts cannot peek into neighboring browser states or read sensitive user parameters, as all reflecting API lookups return mock values or empty arrays.
* **Integrity:** The underlying layout and operational pipeline cannot be silently modified by code injections or telemetry engines due to prototype freezing and the DOM Mutation Firewall.
* **Availability:** By mitigating state floods and systematically shredding detached elements via `AegisMemoryPurgeCore`, the environment remains permanently resilient against out-of-memory exploitation tactics.
