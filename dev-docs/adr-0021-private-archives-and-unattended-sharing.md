# ADR-0021: Private archives with explicit unattended sharing

**Date:** 2026-11-08, amended 2026-11-15
**Status:** Private default and explicit unattended sharing accepted by the repository maintainer. Pinned purego macOS binding accepted by the repository owner on 2026-11-08. The Linux check (verify the open file; no filesystem-type allowlist) decided by the repository owner on 2026-11-15 after the research below, not yet put to the maintainer. On 2026-11-15 the owner decided that macOS treats network volumes as Linux does (checked and noted, not refused by type) and chose the reduced macOS binding described below; neither is yet put to the maintainer.
**Deciders:** Repository maintainer; repository owner where stated.

## Scope

This decision governs filesystem access when a caller explicitly creates an archive with `hdf evidence bundle`. It adds no packaging requirement to pure library APIs or to [requirement-change streaming](adr-0005-hdf-conmon-requirement-change-events.md). In-place edits using `internal/atomicfile`, identity/grant management and SIEM credential lifecycle are outside this archive policy. Access permissions, archive-entry safety and package-read containment are separate requirements; satisfying one does not establish the others.

## Context

`hdf evidence bundle` writes its archive through `writeArchiveAtomically`: it creates a staged archive beside the destination and publishes the complete file. Go's `0600` requests restrictive POSIX mode bits, but on Windows `Chmod` only changes the read-only attribute, and macOS can inherit ACL grants independently of the mode bits. Requesting `0600` therefore does not establish the same privacy guarantee on every platform or filesystem.

The maintainer approved private-by-default protection and deliberate sharing that requires no interactive prompt. Same-account agents can use private files. Different service accounts sometimes exchange artifacts through a directory provisioned for that purpose. Existing CI builds and uploads its archive within one job; subsequent jobs download artifacts through GitHub's access-controlled artifact service. Filesystem ACLs are not a portable artifact-transfer contract.

## Decision

`hdf evidence bundle` takes `--output-access private|inherit`, default `private`. This is a CLI filesystem policy; the converter and engine APIs, the HDF schemas and the ZIP bytes are unchanged. Unknown or empty values are rejected before the package is read. No interactive confirmation, implicit fallback, environment override or automatic privilege elevation is introduced.

| Mode | Linux | macOS | Windows |
|---|---|---|---|
| `private` (default) | Create exclusively with `0600`; before writing, read the owner and mode back from the open file and require the effective user and no group/other bits; on NFSv4, also refuse an inherited ACL entry that grants another principal data access or the right to change the ACL or owner. | Native creation with `0600` and an empty, non-inheriting ACL, then owner/mode/ACL readback before writing. | Create with a protected DACL granting the effective token's user access; verify persistent ACL support and the protected creator-only DACL on the open handle before writing. |
| `inherit` (explicit) | Create with `0666`; the umask and the directory's default ACL decide. | Ordinary native creation with `0666`, umask and directory ACL inheritance. | Native destination-directory ACL inheritance at creation. |

The caller provisions and trusts the destination directory. `inherit` permits its normal access policy; it does not guarantee that another account can read, and can expose data broadly if that directory is broadly accessible. Administrators and operating-system privileges remain outside the ordinary-user isolation guarantee. Neither mode encrypts the archive or protects copies after extraction or transfer.

The policy is applied to the staged file before any byte is written and carried through publication, which refuses to replace a name that already exists unless `--overwrite` is given. Neither mode changes permissions after writing. Replacing an existing archive applies the new-file policy; it does not preserve the old destination's ACL. Failure to establish the requested policy returns an error, removes the staged file and leaves any existing output unchanged. A private-policy failure never retries in inherited mode.

```sh
hdf evidence bundle evidence-package.json -o evidence.zip
hdf evidence bundle evidence-package.json --output-access inherit -o shared/evidence.zip
```

`shared` is an existing directory whose access policy the operator has provisioned for the intended agents. Same-account agents and the existing CI uploader use the default. Cross-account agents select inherited access once in their automation configuration. On POSIX, `inherit` with umask `077` still produces a private file; configuring the shared group or default ACL is an operator prerequisite. A container that runs as root writes a root-owned private archive that an uploader running as another user cannot read: run the container as the invoking user, or choose `inherit`.

### Native creation and the private check

One random-name, exclusive-create loop with platform-specific openers. `os.CreateTemp` cannot supply Windows security attributes or request `0666` for inherited access.

**Linux (decided by the owner 2026-11-15, not yet put to the maintainer).** The private check verifies what the open file shows rather than gating on the filesystem's type. After an exclusive `0600` create, the owner and mode are read with `fstat` on the descriptor; anything but the effective user with no group/other bits is refused. On filesystems with POSIX ACLs (ext4, XFS, Btrfs, tmpfs, ZFS on Linux) a `0600` create sets the ACL mask to `---`, so inherited named entries are ineffective and the readback is sufficient ([acl(5)](https://man7.org/linux/man-pages/man5/acl.5.html), "Object creation and default ACLs"). OverlayFS applies the same local permission model, and its upper layer cannot be NFS ([kernel documentation](https://docs.kernel.org/filesystems/overlayfs.html), "Permission model"). Where the mode cannot be owner-only, the readback fails closed: a default SMB/CIFS mount reads back its `file_mode` (0755), and a FAT volume reads back its mount mask, which the Linux kernel enforces. (On macOS an external FAT volume usually ignores ownership, so every user sees itself as owner; the macOS check refuses ownership-ignored volumes.) On NFSv4 the server must make OWNER@, GROUP@ and EVERYONE@ match the create mode, but trimming inherited named entries is only recommended ([RFC 8881 §6.4.1.1, §6.4.3](https://www.rfc-editor.org/rfc/rfc8881.html#section-6.4)), so the `system.nfs4_acl` attribute is read from the open file and an applicable ALLOW entry that gives anyone but OWNER@ data access (READ_DATA, WRITE_DATA, APPEND_DATA) or control of the file's access (WRITE_ACL, WRITE_OWNER, either of which lets the holder grant itself data access) is refused. EXECUTE is not refused, since it does not expose an archive's contents (owner, 2026-11-15). On network or userspace storage (NFS, SMB/CIFS, FUSE, 9p) one line on stderr notes that the server and its mount options also control access; it is a note, not a refusal, as systemd, GnuPG and the AWS CLI warn rather than refuse. Other Unix build targets refuse `private`, since their ACL models (FreeBSD's NFSv4 ACLs, for one) are not checked, and name `--output-access inherit`.

**macOS.** A local experiment confirmed that ordinary exclusive creation at `0600` inherited an everyone-read ACL. A second isolated experiment used Apple's `openx_np` with `filesec` mode `0600` and an empty ACL carrying `ACL_FLAG_NO_INHERIT`: the newly created empty file had owner-only mode and no inherited ACL. Before writing, the ACL is read back from the open file with `acl_get_fd_np`: `ENOENT` means no ACL, an ACL with any entry is refused, and any other failure fails the check (see Native binding details). Volumes mounted with `MNT_IGNORE_OWNERSHIP` do not enforce permissions and are refused under `private`. A volume without `MNT_LOCAL` (SMB, NFS, AFP, WebDAV) gets the same checks and one stderr note that the server and its mount options also control access; it is not refused for its type (owner, 2026-11-15).

The Go standard library and current `x/sys/unix` do not expose these macOS entry points, and the CLI releases require `CGO_ENABLED=0`. **Owner-approved implementation choice:** pin `github.com/ebitengine/purego` v0.11.3 for a small Darwin-only native binding, preserving the release build model. It supports both released macOS architectures and adds no transitive Go modules; its upstream labels the API beta. The alternative is a Cgo wrapper plus native macOS release builders, which changes the cross-build infrastructure.

**Windows.** Use the effective token's user SID in `D:P(A;;FA;;;<SID>)`, supplied to `CreateFileW` with `CREATE_NEW`; inspect `FILE_PERSISTENT_ACLS` and read back the DACL before the writer receives the handle. Elevated administrator ownership remains within the administrator exclusion above.

Administrator access, server implementation honesty, NFS `AUTH_SYS` trust of client root (host configuration; the RHEL 9 STIG requires RPCSEC_GSS, RHEL-09-231060) and access paths outside the destination mount's access-control model remain outside the guarantee.

### Native binding details

The binding resolves ten libSystem functions with `Dlsym`; a missing one returns an error naming it and closes the library handle, never falling back to ordinary creation. Creation: `acl_init(0)`, `acl_get_flagset_np` and `acl_add_flag_np(ACL_FLAG_NO_INHERIT)` build an empty non-inheriting ACL; `filesec_init` and `filesec_set_property` set `FILESEC_MODE` (a 16-bit `mode_t`, `0600`) and `FILESEC_ACL`; `openx_np` creates the file with `O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC`; `acl_free` and `filesec_free` release both on every path. Readback: `acl_get_fd_np(fd, ACL_TYPE_EXTENDED)`; `ENOENT` means no ACL, any other failure fails the check, and `acl_get_entry(acl, ACL_FIRST_ENTRY)` returning success means an entry is present, which is refused. `openx_np` and `acl_get_fd_np` are called through `purego.SyscallN`, whose trampoline captures errno (collision retries need `EEXIST`, and the readback needs `ENOENT`); the rest are typed `purego.RegisterFunc` bindings that report failure by result. `SyscallN` is `go:uintptrescapes`, so the path (`unix.BytePtrFromString`) and output slots are passed as Go memory for the call's duration without native copies. A returned C int or errno occupies a machine word; only its low 32 bits are read, and a failure without errno is reported as `EIO`. The owner and mode come from `fstat` on the descriptor, as on Linux. Owner choice 2026-11-15: this reduced set replaces an earlier sixteen-function design that also copied the path with `strdup`, allocated output slots with `calloc`, and called `acl_valid`, `filesec_query_property` and `fstatx_np`. SDK values: `FILESEC_MODE=4`, `FILESEC_ACL=5` (`sys/fcntl.h`); `ACL_FLAG_NO_INHERIT=1<<17`, `ACL_TYPE_EXTENDED=0x100`, `ACL_FIRST_ENTRY=0` (`sys/acl.h`).

## Prior art

How established tools create private files, read from their source on 2026-11-15:

| Tool | Creation | Later check | Filesystem or ACL gate |
|---|---|---|---|
| OpenSSH `ssh-keygen` | `umask(077)` | on read, `sshkey_perm_ok` refuses `mode & 077` | none |
| GnuPG agent | exclusive, mode `-rw` (0600) | homedir permissions: warning only | none |
| Kubernetes client-go ([loader.go](https://github.com/kubernetes/client-go/blob/ee1e6ae7a0469c1116e52c11db7abeb50666b6fc/tools/clientcmd/loader.go#L452)) | `os.WriteFile(…, 0600)` | none | none |
| AWS CLI | `os.open(O_CREAT, 0o600)` | `warn_if_permissive`: warning | none |
| git-credential-store | `umask(077)` | none | none |
| Docker CLI | `os.CreateTemp` (0600) | none | none |
| systemd credentials | `fchmod 0400` | on read, exact-mode check | storage: warning only ("not located on encrypted media, using anyway") |
| Terraform ([planfile writer](https://github.com/hashicorp/terraform/blob/297ebd989e773f8e1acf3c5a4d6db4b0fe9e5818/internal/plans/planfile/writer.go#L54)) | ordinary creation | none | none |
| [Win32-OpenSSH](https://github.com/PowerShell/Win32-OpenSSH/wiki/Security-protection-of-various-files-in-win32-openssh#user-private-key-files) | — | on read, owner SID and every ACE | Windows ACLs |

No mainstream tool refuses to write a private file because of the filesystem type.

| Source | Disposition | Evidence and relevance |
|---|---|---|
| Microsoft Win32 security APIs | Adopt native mechanism | [CreateFile security attributes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) establish security at creation; [protected DACLs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptors-for-new-objects) prevent inherited grants. |
| Go `os` and `golang.org/x/sys` v0.49.0 | Adopt | [Go Chmod limitation](https://pkg.go.dev/os#Chmod); existing bindings supply token, security-descriptor, `Fgetxattr` and file APIs. |
| Apple native ACL/file-security APIs | Adopt native mechanism | [`openx_np`](https://github.com/apple-oss-distributions/Libc/blob/main/sys/openx_np.c), [`acl_get_fd`](https://github.com/apple-oss-distributions/Libc/blob/main/posix1e/acl_file.c) and [`filesec`](https://github.com/apple-oss-distributions/Libc/blob/main/gen/filesec.c); creation-time protection succeeded in the isolated macOS probe. No source copied. |
| `ebitengine/purego` v0.11.3 | Adopt; owner approved | [Pinned README](https://github.com/ebitengine/purego/blob/v0.11.3/README.md); Apache-2.0, allowed by dependency review; direct dependency +1, transitive +0. Beta API is the maintenance tradeoff. |
| `naegelejd/go-acl` v0.2.0 | Reject | MIT; uses Cgo and provides no creation-time file opener. |
| ASD STIG V-222587 / APSC-DV-002330 (SC-28), V-222426 / APSC-DV-000470 | Reference | Protect stored information, citing file permissions; discretionary access control. No STIG, SRG or NIST SP 800-53 control asks an application to check filesystem type or ACLs before writing; the RHEL 9 STIG treats network storage as host configuration. |
| NIST SP 800-53 AC-6 | Reference | [Least privilege](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf#page=63) informs the choice; it does not mandate one owner-only ZIP policy. |

Dependency check on 2026-11-08: `golang.org/x/sys` v0.49.0 is BSD-3-Clause, permitted by the dependency-review deny list, not archived, and becomes a direct CLI dependency at the same version.

## Alternatives Considered

### Filesystem-type allowlist on Linux

Under `private`, accept only ext2/3/4, XFS, Btrfs and tmpfs by `fstatfs` and refuse every other filesystem.

- **Pros:** Never trusts storage whose permission model has not been reviewed.
- **Cons:** Rejects ZFS on Linux and container overlays, whose permission model is the same as ext4's; refuses NFS home directories and Kubernetes volumes on NFS, pushing those users to `inherit`, which is weaker than the owner-only file they would otherwise get. No established tool or security guidance gates on filesystem type.
- **Why rejected (owner, 2026-11-15):** Verifying the open file covers the measurable cases (mode readback fails closed on default SMB mounts and FAT mount masks that are not owner-only; the NFSv4 ACL check closes the inherited-entry gap) without refusing storage that provides the protection.

### Always inherit destination permissions

- **Pros:** Native Windows behavior and convenient shared-directory operation.
- **Cons:** Privacy depends entirely on the directory.
- **Why rejected as default:** Does not meet the approved private-by-default policy. Retained as the explicit automation mode.

### Always private, with manual sharing afterward

- **Pros:** Small CLI surface and restrictive creation.
- **Cons:** Requires additional operational steps for cross-account automation.
- **Why rejected:** Deliberate unattended sharing is required.

### Arbitrary user/group grant flags

- **Pros:** Fine-grained grants from a single command.
- **Cons:** Adds identity resolution and a second policy-management surface; the operating system already manages shared-directory policy.
- **Why rejected:** Provisioned directories avoid duplicating identity-policy management.

### Cgo for the macOS native APIs

- **Pros:** Direct calls using Apple's SDK declarations.
- **Cons:** Changes the Cgo-disabled release build and requires macOS builders.
- **Disposition:** Rejected: the owner selected pinned purego to keep the release build model.

### Do nothing or change permissions after writing

- **Pros:** Minimal implementation work.
- **Cons:** Leaves the Windows privacy gap or exposes evidence before permissions change.
- **Why rejected:** Neither meets the creation-time protection requirement.

## Consequences

**What becomes easier:** Agents select a stable noninteractive policy; the private policy establishes protection against ordinary unrelated accounts before any byte is written, on the storage users actually write to.

**What becomes harder:** Cross-account handoffs must deliberately choose inherited access or artifact transfer. Storage whose mode cannot read back owner-only (default SMB mounts, FAT mount masks that are not owner-only) is refused under `private`. Windows and macOS ACL behavior require native verification, not mode assertions or cross-compilation alone. The macOS binding adds a dependency to maintain.

**Risks and mitigation:** Sharing can intentionally broaden access, so the flag's help and the README describe it. A failed private check never falls back. Tests inspect the staged file before writing, the published file, overwrite behavior and cleanup. Broad directory write privileges are not made safe by a file ACL; directory provisioning remains the operator's responsibility.

## Implementation

The access policy ships with no-clobber publication in one pull request, so `private` never exists on one platform without its protection on the others:

- Shared policy, flag, exclusive creation and the Linux/macOS mode readback (`archive_access.go`, `archive_access_unix.go`, `archive_access_other.go`).
- Linux NFSv4 ACL check and the network-storage note.
- macOS non-inheriting ACL creation and readback, with a native macOS CI job.
- Windows protected creator-only DACL.

Each part is built test-first with behavioral RED/GREEN evidence (setup or cross-compilation errors do not count) and independent review; Windows behavior is verified on Windows CI and macOS behavior on macOS.
