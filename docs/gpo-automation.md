# Automating Compliance Scans with Group Policy

This guide explains how to use Group Policy (GPO) to automatically run the RuleForge compliance scanner on all domain-joined Windows machines and collect results in a central location.

## How It Works

1. The portable scanner build is placed on a network share that all machines can read.
2. A GPO deploys a scheduled task to every machine in scope.
3. The scheduled task runs the CLI, writing a per-machine JSON result file to a results share.
4. An administrator reviews the result files from the central share.

No agent or server software is required on client machines.

---

## Prerequisites

- Active Directory domain with Group Policy Management Console (GPMC) installed
- A completed release build: `RuleForge-<version>-portable.zip`
- Two network shares (see below)
- Domain administrator rights

---

## Step 1: Set Up the Network Shares

Create two shared folders on a file server.

**Scanner share** (read-only for domain computers, e.g. `\\fileserver\ComplianceScanner`):
- Extract the contents of `RuleForge-<version>-portable.zip` here.
- The share must contain `cli.exe` and the `rulesets\` folder at its root.
- Set NTFS permissions: `Domain Computers` = Read, `Domain Admins` = Full Control.

**Results share** (write for domain computers, e.g. `\\fileserver\ComplianceResults`):
- Leave this folder empty; each machine will write one file here.
- Set NTFS permissions: `Domain Computers` = Modify, `Domain Admins` = Full Control.

---

## Step 2: Create the Group Policy Object

1. Open **Group Policy Management Console** (gpmc.msc).
2. Right-click the OU containing the target machines and select **Create a GPO in this domain, and Link it here**.
3. Name the GPO (e.g. `Compliance Scanner - Scheduled Scan`).
4. Right-click the new GPO and select **Edit**.

---

## Step 3: Add the Scheduled Task

Inside the GPO editor, navigate to:

```
Computer Configuration
  > Preferences
    > Control Panel Settings
      > Scheduled Tasks
```

Right-click and choose **New > Scheduled Task (At least Windows 7)**.

### General tab

| Field | Value |
|-------|-------|
| Name | Compliance Scan |
| Security options | Run whether user is logged on or not |
| Run with highest privileges | Checked |
| Configure for | Windows 7, Windows Server 2008 R2 |

Set the account to `NT AUTHORITY\SYSTEM` so the task has administrator rights, which the scanner requires for accurate results.

### Triggers tab

Add a trigger for how often you want scans to run. Weekly is typical for compliance baselines.

Example weekly trigger:
- Begin the task: On a schedule
- Weekly, every Monday at 02:00 AM
- Enabled: checked

### Actions tab

Add one action:

| Field | Value |
|-------|-------|
| Action | Start a program |
| Program/script | `\\fileserver\ComplianceScanner\cli.exe` |
| Add arguments | `--ruleset "\\fileserver\ComplianceScanner\rulesets\CMMC Level 1 & 2" --format json --output "\\fileserver\ComplianceResults\%COMPUTERNAME%.json" --no-fail` |

The `--no-fail` flag prevents the scheduled task from being marked as failed when checks fail, which would trigger unnecessary alerts.

### Settings tab

- If the task is already running, do not start a new instance.
- Stop the task if it runs longer than: 1 hour.

Click **OK** and save the GPO.

---

## Step 4: Force Policy Application (Optional)

The policy will apply automatically at the next Group Policy refresh cycle (every 90 minutes by default). To apply immediately on a specific machine for testing:

```powershell
gpupdate /force
```

Verify the task was created:

```powershell
Get-ScheduledTask -TaskName "Compliance Scan"
```

Run it manually for a test:

```powershell
Start-ScheduledTask -TaskName "Compliance Scan"
```

After it finishes, check for the result file on the results share.

---

## Step 5: Review Results

Each machine writes one JSON file named after the computer (e.g. `DESKTOP-ABC123.json`) to the results share. The file follows the standard RuleForge JSON output format:

```json
{
  "results": [ ... ],
  "summary": {
    "total": 94,
    "pass": 71,
    "fail": 18,
    "skip": 5,
    "policy": 0
  }
}
```

You can review files individually or write a script to aggregate them. A simple PowerShell example that lists all machines with at least one failing check:

```powershell
Get-ChildItem \\fileserver\ComplianceResults\*.json | ForEach-Object {
    $data = Get-Content $_ | ConvertFrom-Json
    if ($data.summary.fail -gt 0) {
        [PSCustomObject]@{
            Computer = $_.BaseName
            Fail     = $data.summary.fail
            Pass     = $data.summary.pass
        }
    }
} | Sort-Object Fail -Descending | Format-Table
```

---

## Notes

**Administrator rights**: The scheduled task runs as SYSTEM, which has local administrator access. This is required for checks that query security policy, audit settings, and registry keys. If you use a domain service account instead, it must be a local administrator on each machine.

**First-time file creation**: If the output file does not exist yet, `cli.exe` creates it. If the machine is offline when the task fires, no file is written; the results share simply has no entry for that machine.

**Ruleset updates**: To update the ruleset on all machines, replace the files in the scanner share. No GPO changes are needed because all machines read from the same share at scan time.

**Filtering**: Use `--filter-severity` and `--filter-category` in the arguments field to limit which rules run. For example, to scan only Critical rules:

```
--filter-severity Critical
```

**Scope**: Link the GPO to an OU containing only machines you want to scan. Use GPO security filtering (Security Filtering tab in GPMC) to further restrict which computers receive the policy.
