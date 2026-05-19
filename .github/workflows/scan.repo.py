import os
import requests
import csv
import subprocess

# ==========================================
# CONFIGURATION
# ==========================================

GITHUB_TOKEN = os.getenv("GH_TOKEN")

ORG_NAME = "ambika-org2"

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

VALID_EXTENSIONS = [
    ".yml",
    ".yaml",
    ".tf",
    ".sh",
    ".py",
    ".json",
    ".txt",
    ".md",
    ".properties"
]

# ==========================================
# AWS → AZURE REMEDIATION MAP
# ==========================================

SEARCH_PATTERNS = {

    "aws-actions/configure-aws-credentials": {
        "azure_replacement": "azure/login",
        "auto_replace_possible": "YES",
        "complexity": "Low",
        "suggested_action": "Auto migration possible"
    },

    "AWS_ROLE_ARN": {
        "azure_replacement": "Azure Managed Identity",
        "auto_replace_possible": "REVIEW",
        "complexity": "Medium",
        "suggested_action": "Identity remediation required"
    },

    "aws_secret_access_key": {
        "azure_replacement": "Azure Key Vault Secret",
        "auto_replace_possible": "REVIEW",
        "complexity": "High",
        "suggested_action": "Manual secret remediation required"
    },

    "aws-access-key-id": {
        "azure_replacement": "Azure Service Principal",
        "auto_replace_possible": "REVIEW",
        "complexity": "Medium",
        "suggested_action": "Credential replacement required"
    },

    "secretmanager": {
        "azure_replacement": "Azure Key Vault",
        "auto_replace_possible": "YES",
        "complexity": "Medium",
        "suggested_action": "Secret migration required"
    },

    "secretsmanager_secret_version": {
        "azure_replacement": "Azure Key Vault Versioning",
        "auto_replace_possible": "YES",
        "complexity": "Medium",
        "suggested_action": "Versioning remediation required"
    },

    "kms": {
        "azure_replacement": "Azure Key Vault Encryption",
        "auto_replace_possible": "YES",
        "complexity": "Medium",
        "suggested_action": "Encryption remediation required"
    },

    "boto3": {
        "azure_replacement": "Azure SDK",
        "auto_replace_possible": "NO",
        "complexity": "High",
        "suggested_action": "Code remediation required"
    },

    "aws secretsmanager": {
        "azure_replacement": "az keyvault",
        "auto_replace_possible": "REVIEW",
        "complexity": "High",
        "suggested_action": "CLI remediation required"
    }
}

# ==========================================
# GET REPOSITORIES
# ==========================================

repos_url = f"https://api.github.com/orgs/{ORG_NAME}/repos"

response = requests.get(repos_url, headers=HEADERS)

repos = response.json()

results = []

os.makedirs("./temp", exist_ok=True)

# ==========================================
# SCAN REPOSITORIES
# ==========================================

for repo in repos:

    repo_name = repo["name"]

    print(f"\nScanning repository: {repo_name}")

    local_path = f"./temp/{repo_name}"

    subprocess.run(["rm", "-rf", local_path])

    clone_command = [
        "git",
        "clone",
        f"https://x-access-token:{GITHUB_TOKEN}@github.com/{ORG_NAME}/{repo_name}.git",
        local_path
    ]

    clone_result = subprocess.run(
        clone_command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if clone_result.returncode != 0:
        print(f"Failed to clone {repo_name}")
        continue

    for root, dirs, files in os.walk(local_path):

        for file in files:

            if not file.endswith(tuple(VALID_EXTENSIONS)):
                continue

            file_path = os.path.join(root, file)

            try:

                with open(
                    file_path,
                    "r",
                    encoding="utf-8",
                    errors="ignore"
                ) as f:

                    lines = f.readlines()

                    updated_lines = []

                    for line_number, line in enumerate(lines, start=1):

                        remediated_line = line
                        line_lower = line.lower()

                        for pattern, details in SEARCH_PATTERNS.items():

                            if pattern.lower() in line_lower:

                                if details["auto_replace_possible"] == "YES":

                                    if pattern in AUTO_REPLACEMENTS:

                                        remediated_line = remediated_line.replace(
                                            pattern,
                                            AUTO_REPLACEMENTS[pattern]
                                        )

                                results.append({

                                    "Repository": repo_name,

                                    "File": file_path.replace(
                                        local_path,
                                        ""
                                    ),

                                    "Line_Number": line_number,

                                    "AWS_Usage": pattern,

                                    "Matched_Line": line.strip(),

                                    "Azure_Replacement":
                                        details["azure_replacement"],

                                    "Auto_Replace_Possible":
                                        details["auto_replace_possible"],

                                    "Complexity":
                                        details["complexity"],

                                    "Suggested_Action":
                                        details["suggested_action"]
                                })

                        updated_lines.append(remediated_line)

                remediation_path = file_path.replace(
                    "./temp",
                    "./remediated"
                )

                os.makedirs(
                    os.path.dirname(remediation_path),
                    exist_ok=True
                )

                with open(
                    remediation_path,
                    "w",
                    encoding="utf-8"
                ) as out:

                    out.writelines(updated_lines)

            except Exception as e:
                print(f"Could not read file: {file_path}")


# CREATE BRANCH + COMMIT CHANGES

subprocess.run([
    "git", "-C", local_path,
    "checkout", "-b", "azure-remediation"
])

subprocess.run([
    "git", "-C", local_path,
    "add", "."
])

subprocess.run([
    "git", "-C", local_path,
    "commit",
    "-m",
    "Auto Azure remediation"
])

subprocess.run([
    "git", "-C", local_path,
    "push",
    "origin",
    "azure-remediation"
])

# ==========================================
# GENERATE CSV REPORT
# ==========================================

with open(
    "scan-report.csv",
    "w",
    newline="",
    encoding="utf-8"
) as csvfile:

    fieldnames = [

        "Repository",
        "File",
        "Line_Number",
        "AWS_Usage",
        "Matched_Line",
        "Azure_Replacement",
        "Auto_Replace_Possible",
        "Complexity",
        "Suggested_Action"
    ]

    writer = csv.DictWriter(
        csvfile,
        fieldnames=fieldnames
    )

    writer.writeheader()

    if results:

        writer.writerows(results)

    else:

        writer.writerow({

            "Repository": "No AWS usage detected",
            "File": "",
            "Line_Number": "",
            "AWS_Usage": "",
            "Matched_Line": "",
            "Azure_Replacement": "",
            "Auto_Replace_Possible": "",
            "Complexity": "",
            "Suggested_Action": ""
        })

print("\n===================================")
print("Scan completed successfully.")
print("Report generated: scan-report.csv")
print("Remediated files generated under ./remediated")
print("===================================")
