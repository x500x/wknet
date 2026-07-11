# Pack200 fixtures

Offline interoperability corpus for the kernel Pack200 decoder. JDK tools are used only to generate fixtures; the runtime decoder has no Java dependency.

## Stable-format matrix

| Directory | Pack200 format | Classfile major | Native packer |
|---|---:|---:|---|
| `corpus/jdk5` | `150.7` | 49 | Azul Zulu 6 |
| `corpus/jdk6` | `160.1` | 50 | Azul Zulu 6 |
| `corpus/jdk7` | `170.1` | 51 | Eclipse Temurin 8 |
| `corpus/jdk8` | `171.0` | 52 | Eclipse Temurin 8 |

Directory names identify the target format/classfile generation, not the packer release. Zulu 6 emits the published `150.7` format; the archived Zulu 7 packer emitted only `160.1`, so the `170.1` corpus uses a Java 7 input JAR with the Temurin 8 native packer.

Each directory contains deterministic `input.jar`, raw `archive.pack`, gzip `archive.pack.gz`, and the native `unpack200` result `reference.jar`. Tests verify SHA-256, raw/gzip decoding, classfile version, entry names, and `SourceFile` semantics.

`corpus/jdk8/custom-attributes.pack` covers:

- class, field, method, and code attribute contexts;
- replication, union ranges, callable/forward/back-call layouts;
- overflow attribute indexes;
- constant-pool references and BCI/offset relocation.

## Integrity and regeneration

- `corpus/SHA256SUMS`: hashes for every stored corpus artifact.
- `corpus/provenance.json`: distribution/version, download URL, JDK archive and `pack200.exe` hashes, format version, layouts, and per-file hashes.
- `GenerateJdkPack200Corpus.ps1`: accepts explicit JDK homes plus ASM and Commons Compress JAR paths; it does not download or store JDK installations.
- Synthetic fixtures use Apache Commons Compress 1.26.1 and ASM 9.7.1; interoperability fixtures use native `pack200`/`unpack200`.

Native JDK 8 `pack200` fails on a user-defined `KQ` band (`null index for 7`). Field-specific `KQ` behavior is therefore covered by layout/compiler and descriptor-directed relocation tests, and the generator limitation is recorded explicitly rather than represented as native corpus output.
