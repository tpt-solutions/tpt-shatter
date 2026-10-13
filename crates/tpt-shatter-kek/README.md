# tpt-shatter-kek

Seals a node's keys under a key-encryption key (KEK), and splits the KEK so that two
custodians must be present to start the node.

| Command | What it does |
|---|---|
| `tpt-shatter-kek generate <dir> <name>...` | Writes fresh random 32-byte keys, one file each, mode 0400. |
| `tpt-shatter-kek seal <dir> <blob>` | Shamir custody. Seals every key file in `dir` into `blob`, and prints three custodian shares. The shares are printed once. |
| `tpt-shatter-kek seal <dir> <blob> --kms-wrap <program>` | Cloud custody. The program wraps the KEK, and only the wrapped KEK is stored. |
| `tpt-shatter-kek unseal <blob> <outdir>` | Shamir custody. Reads two shares from stdin, one per line, and writes the keys into `outdir`. |
| `tpt-shatter-kek unseal <blob> <outdir> --kms-unwrap <program>` | Cloud custody. The program unwraps the KEK. Use a tmpfs for `outdir`. |

The blob is ChaCha20-Poly1305 under a random KEK. In Shamir custody the KEK is split 2-of-3
with Shamir's scheme over GF(256) (`blahaj`), and one share reveals nothing about it. In cloud
custody the KEK is wrapped by an external program, which the library never sees. The custody
mode is authenticated in the blob header. The procedure is in `docs/RUNBOOK.md`, section 1.

The external programs are run directly, with no shell, and are named only on the command line.

This is not a KMS. It has no access control and no audit of its own. The custody procedure is
part of the security boundary, and the Shamir implementation has not been independently audited.
