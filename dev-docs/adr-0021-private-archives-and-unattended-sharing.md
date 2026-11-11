# ADR-0021: Private archives with explicit unattended sharing

**Date:** 2026-11-08
**Status:** Accepted
**Deciders:** Repository maintainer.
**Supersedes:** The Windows inherited-permission default in [ADR-0020](adr-0020-siem-evidence-package-delivery.md#cli-contract). All evidence inventory, preservation, verification and publication rules remain in force.

## Scope

This decision governs filesystem access when a caller explicitly creates an archive with `hdf evidence bundle` or `hdf convert --bundle`. It adds no packaging requirement to pure library APIs or to [requirement-change streaming](adr-0005-hdf-conmon-requirement-change-events.md). In-place edits using `internal/atomicfile`, identity/grant management and SIEM credential lifecycle are outside this archive policy. Access permissions, archive-entry safety and package-read containment are separate requirements; satisfying one does not establish the others.

## Context

Both `hdf evidence bundle` and `hdf convert --bundle` use `writeArchiveAtomically` in the CLI. It creates a temporary archive beside the destination and publishes the complete file. Go's `0600` requests restrictive POSIX mode bits, but on Windows `Chmod` only changes the read-only attribute. macOS can inherit ACL grants independently of those mode bits. Requesting `0600` therefore does not establish the same privacy guarantee on every platform or filesystem.

The maintainer approved private-by-default protection and deliberate sharing that requires no interactive prompt. Same-account agents can use private files. Different service accounts sometimes exchange artifacts through a directory provisioned for that purpose. Existing CI builds and uploads its archive within one job; subsequent jobs download artifacts through GitHub's access-controlled artifact service. Filesystem ACLs are not a portable artifact-transfer contract.

## Decision

Expose the same `--output-access private|inherit` option on both archive commands. Default to `private`. This is a CLI filesystem policy; pure TypeScript and Go converter APIs, HDF schemas and ZIP bytes are unchanged. Reject unknown or empty values, and reject the option on `convert` without `--bundle`. No interactive confirmation, implicit fallback, environment override or automatic privilege elevation is introduced.

| Mode | Linux/POSIX mode enforcement | macOS | Windows |
|---|---|---|---|
| `private` (default) | Request `0600`; before writing verify the open file's owner is the effective user and its group/other mode bits are zero. Mode inspection alone is insufficient on filesystems with independent ACL grants; see the fail-closed capability boundary below. | Native creation with `0600` and an empty, non-inheriting ACL, followed by mode/owner/ACL readback before writing. | Create with a protected DACL granting the effective token's user access; verify persistent ACL support and the actual protected creator-only DACL on the open handle before writing. |
| `inherit` (explicit) | Request ordinary file mode `0666` at creation; umask and filesystem default ACL determine access. | Ordinary native creation with `0666`, umask and directory ACL inheritance. | Native destination-directory ACL inheritance at creation. |

The caller provisions and trusts the destination directory. `inherit` permits its normal access policy; it does not guarantee that another account can read, and can expose data broadly if that directory is broadly accessible. Administrators and operating-system privileges remain outside the ordinary-user isolation guarantee. Neither mode encrypts the archive or protects copies after extraction or transfer.

Apply the selected policy to the temporary file before writing any bytes, and carry it through existing hard-link/rename publication. Neither mode changes permissions after writing. `--overwrite` remains separate explicit consent. Replacing an existing archive applies the selected new-file policy; it does not preserve the old destination's ACL. Failure to establish the requested policy must return an error, clean up the staged file, and leave any existing output unchanged. A private-policy failure never retries in inherited mode.

Unattended usage:

```sh
hdf convert scan.json --to ecs --bundle -o export.zip
hdf convert scan.json --to ecs --bundle --output-access inherit -o shared/export.zip
hdf evidence bundle evidence-package.json --output-access inherit -o shared/evidence.zip
```

`shared` is an existing directory whose access policy the operator has provisioned for the intended agents. Same-account agents and the existing CI uploader use the default. Cross-account agents can select inherited access once in their automation configuration. On POSIX, `inherit` with umask `077` can still produce a private file; configuring the shared group/default ACL is an operator prerequisite. Authenticated artifact transfer is the existing cross-job mechanism; no new transport is needed.

### Native creation and filesystem capability checks

Use one random-name/exclusive-create loop shared by both commands, with platform-specific file openers. `os.CreateTemp` cannot supply Windows security attributes or request `0666` for inherited access. On Windows, use the effective token's user SID in `D:P(A;;FA;;;<SID>)`, supplied to `CreateFileW` with `CREATE_NEW`; inspect `FILE_PERSISTENT_ACLS` and read back the DACL before the writer receives the handle. Elevated administrator ownership remains within the administrator exclusion above.

An isolated macOS probe showed that ordinary `0600` creation inherited an everyone-read ACL. Native `openx_np` creation with an empty, non-inheriting ACL prevented that grant. The implementation therefore queries the open file's ACL with `fstatx_np` and `filesec_query_property`, distinguishing successful absence from a failed query and rejecting any ACL entries or unexpected error.

The standard library and existing `x/sys/unix` do not expose the required macOS entry points. Use `github.com/ebitengine/purego` v0.11.3 for a Darwin-only binding to retain `CGO_ENABLED=0` releases on arm64 and amd64. Its beta API is a maintenance tradeoff; Cgo would require a different release build model. Native execution on both architectures is required to verify the binding.

**Fail-closed capability boundary:** Linux private output uses an open-handle `fstatfs` check for kernel filesystems with POSIX mode/ACL enforcement: ext2/3/4, XFS, Btrfs and tmpfs. It then verifies actual owner and group/other mode bits before writing. POSIX ACL masks are limited by those mode bits ([Linux ACL contract](https://man7.org/linux/man-pages/man5/acl.5.html)); OverlayFS is excluded because its filesystem identity does not establish the underlying storage semantics ([kernel documentation](https://docs.kernel.org/filesystems/overlayfs.html)). macOS private output requires APFS or HFS with `MNT_LOCAL` set and `MNT_IGNORE_OWNERSHIP` clear, native non-inheriting ACL creation and successful owner/mode/ACL readback. Windows requires persistent ACL support and exact protected-DACL readback. Unknown types, network or userspace filesystems not covered by these checks, and failed capability queries are rejected before any evidence bytes are written. Container automation can mount supported storage for private output rather than writing to an unverified overlay layer. An error recommends a supported local destination or deliberate inherited access where the operator trusts the storage policy; the program never changes mode automatically. Other Go build targets return an unsupported-private-policy error and retain ordinary inherited creation.

This is a bounded filesystem support policy, not a claim about arbitrary network storage. NFSv4 ACL/mode synchronization permits implementation choices ([RFC 8881 sections 6.3–6.4](https://www.rfc-editor.org/rfc/rfc8881.html#section-6.3)). Administrator access, filesystem/server implementation honesty, and alternative access paths outside the destination mount's access-control model remain outside the guarantee. Regression tests must explicitly exercise an ignore-ownership volume result, a missing MNT_LOCAL flag, unknown filesystem types and failed queries, as unsupported filesystem results and verify that no writer is invoked or destination replaced. Adding a supported filesystem requires its permission semantics and tests to be reviewed.

### Native binding constraints

The [Darwin binding](../hdf-cli/cmd/hdf/cmd/archive_access_darwin.go) uses checked symbol lookup, typed calls and native-memory allocation. Operations whose behavior depends on errno use the value captured by the call trampoline, never a later thread-local read from Go. SDK-selected symbols differ between amd64 and arm64. Missing symbols, allocation failures and invalid ACLs return errors without falling back to ordinary creation; allocations and handles are released on failure. Native tests are required because cross-compilation cannot establish these properties.

## Prior art

| Source | Disposition | Evidence and relevance |
|---|---|---|
| Microsoft Win32 security APIs | Adopt native mechanism | [CreateFile security attributes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) establish security at creation; [protected DACLs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptors-for-new-objects) prevent inherited grants. |
| Go `os` and existing `golang.org/x/sys/windows` v0.49.0 | Adopt | [Go Chmod limitation](https://pkg.go.dev/os#Chmod); existing Windows bindings supply token, security-descriptor and file APIs. Windows needs no new module or external command. |
| Apple native ACL/file-security APIs | Adopt native mechanism | [`openx_np`](https://github.com/apple-oss-distributions/Libc/blob/main/sys/openx_np.c), [`acl_get_fd`](https://github.com/apple-oss-distributions/Libc/blob/main/posix1e/acl_file.c) and [`filesec`](https://github.com/apple-oss-distributions/Libc/blob/main/gen/filesec.c); creation-time protection succeeded in the isolated macOS probe. No source copied. |
| `ebitengine/purego` v0.11.3 | Adopt; owner approved | [Pinned README](https://github.com/ebitengine/purego/blob/v0.11.3/README.md), Apache-2.0 LICENSE read in full and allowed by dependency review; direct dependency +1, transitive dependencies +0. Calls native APIs without Cgo. Beta API is the maintenance tradeoff. |
| `naegelejd/go-acl` v0.2.0 | Reject for this implementation | MIT LICENSE inspected; uses Cgo and does not provide the needed creation-time file opener. It does not preserve the existing release build model. |
| Kubernetes client-go configuration writer | Reference | [Pinned writer](https://github.com/kubernetes/client-go/blob/ee1e6ae7a0469c1116e52c11db7abeb50666b6fc/tools/clientcmd/loader.go#L452) uses Go `0600`; that alone does not promise Windows privacy. |
| Terraform plan archive writer | Reference | [Pinned writer](https://github.com/hashicorp/terraform/blob/297ebd989e773f8e1acf3c5a4d6db4b0fe9e5818/internal/plans/planfile/writer.go#L54) uses ordinary file creation, illustrating inherited access for exported artifacts. |
| Win32-OpenSSH private keys | Reference | [Policy](https://github.com/PowerShell/Win32-OpenSSH/wiki/Security-protection-of-various-files-in-win32-openssh#user-private-key-files) requires restrictive access for private material. |
| NIST SP 800-53 AC-6 | Reference | [Least privilege](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf#page=63) informs the choice; it does not mandate one owner-only ZIP policy. |

The selected `purego` binding is Apache-2.0 and adds no transitive Go modules; existing `x/sys` is BSD-3-Clause. No upstream implementation is copied.

## Alternatives Considered

### Always inherit destination permissions

- **Pros:** Native Windows behavior and convenient shared-directory operation.
- **Cons:** Privacy depends entirely on the directory, unlike the POSIX private default.
- **Why rejected as default:** Does not meet the approved consistent private-by-default policy. Retained as explicit automation mode.

### Always private, with manual sharing afterward

- **Pros:** Small CLI surface and restrictive creation.
- **Cons:** Requires additional operational steps for cross-account automation.
- **Why rejected:** The owner explicitly requires deliberate unattended sharing.

### Arbitrary user/group grant flags

- **Pros:** Fine-grained grants from a single command.
- **Cons:** Adds identity resolution and a second policy-management surface; the operating system already manages shared-directory policy.
- **Why rejected:** Native platform APIs and preconfigured directories avoid duplicating identity-policy management. A native call binding is a separate implementation dependency, not an ACL policy engine.

### Cgo for the macOS native APIs

- **Pros:** Direct calls using Apple's SDK declarations, without a third-party Go native-call binding.
- **Cons:** Changes the current Cgo-disabled release build and requires suitable macOS builders/toolchains.
- **Disposition:** Rejected for this change: the owner selected pinned purego to retain the existing release build model. Native Go binding verification is still required.

### Do nothing or change permissions after writing

- **Pros:** Minimal implementation work.
- **Cons:** Leaves the Windows privacy gap or exposes temporary evidence before permissions change.
- **Why rejected:** Neither meets the approved creation-time protection requirement.

## Consequences

**What becomes easier:** Agents can select a stable noninteractive policy; both archive commands share the implementation. The private policy requires protection against ordinary unrelated accounts before writing; filesystem capability checks must succeed before writing.

**What becomes harder:** Cross-account handoffs must deliberately choose inherited access or artifact transfer. Filesystems whose protection cannot be established must be rejected in private mode. Windows and macOS ACL behavior require native verification, not mode assertions or cross-compilation alone. The macOS binding adds a dependency that must be maintained and tested against supported Go releases.

**Risks and mitigation:** Sharing can intentionally broaden access, so help and docs describe it at the option. Unsupported security capabilities fail without fallback. Tests inspect the staged file before writing, the published file, overwrite behavior, cleanup and identity boundaries. Broad directory write privileges are not made safe by a file ACL; directory provisioning remains the operator's responsibility.

## Verification boundary

Tests inspect access on the staged file before writing and after publication, plus overwrite survival, cleanup and unsupported filesystem behavior. Windows DACL and macOS ACL checks require native execution; a mode-bit assertion is insufficient. These checks establish the bounded access policy above, not encryption, signature authenticity or complete archive security.

The [shared archive creator](../hdf-cli/cmd/hdf/cmd/archive_access.go) applies the selected policy to both commands. Current product verification and unresolved findings belong in the PR review evidence and issue tracker, not in this decision record.
