# Release Process

Releases are built and published by GitHub Actions. Pushing a version tag triggers the release workflow, which runs the full test suite, builds the Windows installer, packages a portable zip, and creates a draft GitHub release.

Every push to `main` and every pull request also runs the full test suite automatically via the CI workflow, across Windows and Ubuntu on Python 3.10, 3.11, and 3.12. A separate lint job runs `ruff check .` on each PR.

## Prerequisites

- Push access to the repository
- GitHub Actions enabled on the repository

## Steps to Release

**1. Confirm the build is in a good state.**

Make sure all changes are committed and pushed to `main`. The CI workflow runs on every push, so check the Actions tab to confirm the latest run passed on all matrix combinations.

**2. Create and push a version tag.**

```bash
git tag v1.2.3
git push origin v1.2.3
```

The tag must start with `v` followed by a version number (e.g. `v1.0.0`, `v2.1.3`).

New artifacts produced by the build are the same two files (installer and portable zip). The portable zip now includes `ui/report_html.py`, which is bundled automatically by PyInstaller.

**3. Monitor the workflow.**

Go to the Actions tab on GitHub. The "Release" workflow starts automatically. It:

1. Runs the full pytest test suite — the build aborts if any test fails.
2. Builds with PyInstaller.
3. Signs the exe (if a signing certificate is configured).
4. Packages the portable zip.
5. Compiles the Inno Setup installer.
6. Signs the installer (if a signing certificate is configured).
7. Creates a draft GitHub release with both artifacts attached.

**4. Publish the draft release.**

When the workflow finishes, a draft release appears under the Releases tab with two artifacts attached:

- `ComplianceScannerSetup-<version>.exe` - Windows installer
- `RuleForge-<version>-portable.zip` - portable copy, no installation required

Review and edit the auto-generated release notes, then click **Publish release** to make it public.

## Versioning

The version number comes from the tag. Pushing `v1.2.3` produces artifacts labeled `1.2.3`. The fallback version in `installer.iss` (`1.0.0`) is only used for local builds run directly with `build.bat`.

## Code Signing (Optional)

When present, the workflow signs the exe before packaging the portable zip, then signs the installer. Both artifacts end up signed. The signing certificate file is written to a temporary path, used, and always deleted in a `finally` block — even if signing fails — so credentials are never left on disk.

Add two secrets to the repository under Settings > Secrets and variables > Actions:

| Secret | Value |
|--------|-------|
| `SIGN_CERT_PFX` | Base64-encoded `.pfx` certificate file |
| `SIGN_CERT_PASSWORD` | Password for the certificate |

To base64-encode a certificate on Windows:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\path\to\cert.pfx")) | Set-Clipboard
```

Paste the clipboard contents as the value for `SIGN_CERT_PFX`.

When no signing secrets are present, the workflow skips the signing steps and produces unsigned artifacts. Windows SmartScreen will show a warning on first run of unsigned executables — users can click **More info → Run anyway** to proceed.

## Deleting a Tag

If you pushed a tag by mistake:

```bash
git tag -d v1.2.3
git push origin :refs/tags/v1.2.3
```

Delete the corresponding draft release on GitHub under Releases as well.
