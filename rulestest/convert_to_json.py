import pandas as pd
import json
import os
import re
import copy

DEF_OS = {"windows-client", "windows-server", "linux", "debian"}


def safe_filename(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", value)

def normalize_os_list(applied_os):
    if pd.isna(applied_os):
        return DEF_OS
    return {
        os.strip().lower()
        for os in str(applied_os).split(",")
    }


def empty_check_details():
    return {
        "windows-client": {"checks": []},
        "windows-server": {"checks": []},
        "linux": {"checks": []},
        "debian": {"checks": []}
    }

def base_check_details():
    return {
        "windows-client": {"checks": []},
        "windows-server": {"checks": []},
        "debian": {"checks": []},
        "linux": {"checks": []}
    }

def build_control(row, *, is_sub=False):

    return {
        "id": row["Sub Control Code"] if is_sub else row["Control Code"],
        "control_number": row["Control Code"],
        "title": "no-title",
        "description": row["Description"],
        "category": row["Control Family"],
        "target_os": (
            [os.strip().lower() for os in str(row["Applied OS"]).split(",")]
            if pd.notna(row["Applied OS"])
            else ["windows-client", "windows-server", "linux", "debian"]
        ),
        "check_type": "command",
        "check_details": base_check_details(),
        "expected_result": "System access is limited to authorized users, processes, and devices.",
        "severity": "High",
        "remediation": (
            row["Recommendations"]
            if pd.notna(row["Recommendations"])
            else "Instructions to remediate non-compliance"
        ),
        "tags": [
            row["Control Family"],
            row["Control Code"]
        ],
        "sub_controls": []
    }

if __name__ == "__main__":
    DEF_OS = {"windows-client", "windows-server", "linux", "debian"}
    df = pd.read_csv("CIS499_ Frameworks.csv")
    OUTPUT_DIR = "controls"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    grouped = df.groupby("Control Code")

    for control_code, group in grouped:
        first = group.iloc[0]

        control_json = {
            "id": control_code,
            "control_number": control_code,
            "title": "no-title",
            "description": first["Description"],
            "category": first["Control Family"],
            "target_os": sorted(list(DEF_OS)),
            "check_details": empty_check_details(),
            "severity": "High",
            "remediation": (
                first["Recommendations"]
                if pd.notna(first["Recommendations"])
                else "Instructions to remediate non-compliance"
            ),
            "tags": [
                first["Control Family"],
                control_code
            ]
        }

        for _, row in group.iterrows():
            applicable_oses = normalize_os_list(row.get("Applied OS"))

            check = {
                "check_type": "command",
                "name": "TITLE OF CHECK",
                "sub_control": row["Sub Control Code"][-1:],
                "command": "NA",
                "expected_result": "NA",
                "purpose": "NA"
            }

            for os_name in applicable_oses:
                if os_name in control_json["check_details"]:
                    control_json["check_details"][os_name]["checks"].append(check.copy())
        filename = safe_filename(control_code) + ".json"
        path = os.path.join(OUTPUT_DIR, filename)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(control_json, f, indent=2)

    print(f"Generated {len(grouped)} control files in '{OUTPUT_DIR}/'")
