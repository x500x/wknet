# EXI fixtures

Offline interoperability corpus for the kernel EXI decoder. Java is required only to regenerate fixtures; the runtime decoder has no Java dependency.

## Coverage

| Case | Alignments | Expected result |
|---|---|---|
| Schema-less Infoset | bit-packed, byte-aligned, pre-compression, compression | Infoset-equivalent XML |
| `xsi:nil=true` / `xsi:nil=false` | all four | Canonical nil attribute and valid element grammar |
| `xsi:nil=true` with character content | all four | `STATUS_INVALID_NETWORK_RESPONSE` |

The reference encoder is Siemens EXIficient Core 1.0.7 (`com.siemens.ct.exi:exificient-core:1.0.7`, Apache-2.0). Regenerate with `GenerateExiCorpus.ps1`, passing an explicit Java home and dependency JAR paths.

## Integrity and scope

- `corpus/SHA256SUMS`: hashes for every EXI and expected XML artifact.
- `corpus/provenance.json`: encoder/dependency hashes, alignments, and source Infosets.
- Supported scope: W3C EXI 1.0 Second Edition without an external Schema.
- Explicit rejection: external Schema and strict grammar streams return `STATUS_NOT_SUPPORTED`.
