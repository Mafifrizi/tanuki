# Empirical Validation

Tanuki is validated against live hybrid infrastructure: an unprivileged Kali Linux workstation (`192.168.56.105`, UID 1000) connecting directly to an Active Directory Domain Controller running Windows Server 2022 (`192.168.56.106`, `DC01.lab.local`).

The run proves each rung of the operator lifecycle end to end, from pre-flight triage to Blue Team forensic telemetry on the DC itself.

## Milestone 1: Pre-flight environment diagnostic and OPSEC sensor probe

Health audit inspecting DNS resolution, KDC reachability, keytab validity, clock drift, and local endpoint telemetry hooks.

<p align="center">
  <img src="../assets/01_tanuki_doctor.png" alt="Tanuki Doctor pre-flight diagnostics" width="850">
</p>

## Milestone 2: RFC 4120 binary keytab inspection and enctype auditing

In-line parser dissecting raw keytab binary structures, extracting principal entries, Kerberos enctypes (AES-256 vs RC4), and Key Version Numbers.

<p align="center">
  <img src="../assets/02_tanuki_keytab.png" alt="Tanuki keytab binary inspection" width="850">
</p>

## Milestone 3: Native userspace TGT acquisition and clock drift tolerance

Direct userspace AS-REQ negotiation establishing a Kerberos TGT without root permissions, healing workstation-to-KDC clock skew in memory.

<p align="center">
  <img src="../assets/03_tanuki_auth_tgt.png" alt="Tanuki native userspace TGT acquisition" width="850">
</p>

## Milestone 4: Quantitative blast radius and identity privilege tiering

Calculates blast radius impact (0-100 score), classifies account privileges (Tier 0/1/2), audits accessible SPNs, and generates deterministic Active Directory mitigation cmdlets.

<p align="center">
  <img src="../assets/04_tanuki_blast_radius.png" alt="Tanuki blast radius and privilege tiering" width="850">
</p>

## Milestone 5: Closed-loop Blue Team forensic telemetry on DC01

Forensic verification inspecting the Windows Server 2022 Security Event log, proving live ticket requests attributed to `192.168.56.105` with modern AES-256 (`0x12`).

<p align="center">
  <img src="../assets/05_dc01_event4769.png" alt="DC01 Security Event log forensic telemetry" width="850">
</p>

## Automated test coverage

Beyond the live lab run, Tanuki ships a full automated suite: 500+ Python unit tests and 39 Rust tests (library plus integration), covering unit, boundary, pairwise, and live-wire scenarios. The Rust core builds with zero compiler warnings under `#![forbid(unsafe_code)]`.
