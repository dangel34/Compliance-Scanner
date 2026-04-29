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

## Repository Secrets Reference

All secrets live under **Settings → Secrets and variables → Actions** on GitHub.

| Secret | Required | Purpose | How to obtain |
|--------|----------|---------|---------------|
| `SONAR_TOKEN` | Yes (for SonarCloud scan) | Authenticates the CI SonarCloud scan job | sonarcloud.io → My Account → Security → Generate Token |
| `SIGN_CERT_PFX` | No (code signing only) | Base64-encoded `.pfx` certificate for signing the exe and installer | Base64-encode your `.pfx` file (see below) |
| `SIGN_CERT_PASSWORD` | No (code signing only) | Password for the `.pfx` certificate | From your certificate provider |

## SonarCloud Setup

The CI workflow uploads test coverage and triggers a SonarCloud scan after the test matrix passes. To enable it:

1. Create a project at [sonarcloud.io](https://sonarcloud.io) linked to this GitHub repo.
2. Go to **My Account → Security** and generate a token named `ruleforge-github-actions`.
3. Add it as `SONAR_TOKEN` in GitHub repo secrets.
4. Update `sonar-project.properties` in the repo root — replace `YOUR_ORG_KEY` with your SonarCloud organization key (visible in the URL: `sonarcloud.io/organizations/<key>`).

Without `SONAR_TOKEN`, the `sonar` CI job will fail. If you want to disable SonarCloud entirely, remove the `sonar:` job from `.github/workflows/ci.yml`.

## Code Signing (Optional)

When present, the workflow signs the exe before packaging the portable zip, then signs the installer. Both artifacts end up signed. The signing certificate file is written to a temporary path, used, and always deleted in a `finally` block — even if signing fails — so credentials are never left on disk.

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
