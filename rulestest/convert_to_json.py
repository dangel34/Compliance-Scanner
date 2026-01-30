import pandas as pd
import json
import os
import re




def safe_filename(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", value)

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
    df = pd.read_csv("CIS499_ Frameworks.csv")
    OUTPUT_DIR = "controls"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    grouped = df.groupby("Control Code")

    for control_code, group in grouped:
        first_row = group.iloc[0]
        main_control = build_control(first_row, is_sub=False)

        for _, row in group.iterrows():
            sub_control = build_control(row, is_sub=True)
            sub_control["sub_controls"] = []
            main_control["sub_controls"].append(sub_control)

        filename = safe_filename(control_code) + ".json"
        path = os.path.join(OUTPUT_DIR, filename)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(main_control, f, indent=2)

    print(f"Generated {len(grouped)} control files in '{OUTPUT_DIR}/'")
