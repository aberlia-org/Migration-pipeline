import os
import requests
import csv

GITHUB_TOKEN = os.getenv("GH_TOKEN")
ORG_NAME = "aberlia-org"

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

SEARCH_PATTERNS = [
    "aws-actions/configure-aws-credentials",
    "AWS_ROLE_ARN",
    "secretsmanager",
    "aws_secret_access_key",
    "secretmanager_secret_version",
    "kms",
    "aws-access-key-id"
]

# Mapping AWS patterns to Azure replacements
REMEDIATION_MAP = {
    "aws-actions/configure-aws-credentials": {
        "replacement": "azure/login",
        "complexity": "Low",
        "action": "Auto Migration Possible"
    },
    "AWS_ROLE_ARN": {
        "replacement": "Azure Federated Identity",
        "complexity": "Medium",
        "action": "Identity Migration Required"
    },
    "secretsmanager": {
        "replacement": "Azure Key Vault",
        "complexity": "Medium",
        "action": "Secret Migration Required"
    },
    "aws_secret_access_key": {
        "replacement": "Azure Key Vault Secret",
        "complexity": "High",
        "action": "Manual Review Needed"
    },
    "secretmanager_secret_version": {
        "replacement": "Azure Key Vault Versioning",
        "complexity": "High",
        "action": "Manual Remediation Needed"
    },
    "kms": {
        "replacement": "Azure Key Vault Encryption",
        "complexity": "Medium",
        "action": "Encryption Migration Required"
    },
    "aws-access-key-id": {
        "replacement": "Azure Service Principal",
        "complexity": "Medium",
        "action": "Credential Migration Required"
    }
}

repos_url = f"https://api.github.com/orgs/{ORG_NAME}/repos"
response = requests.get(repos_url, headers=HEADERS)
repos = response.json()

results = []

for repo in repos:
    repo_name = repo['name']
    print(f"Scanning repo: {repo_name}")

    contents_url = f"https://api.github.com/repos/{ORG_NAME}/{repo_name}/contents/.github/workflows"
    contents_response = requests.get(contents_url, headers=HEADERS)

    if contents_response.status_code != 200:
        continue

    workflow_files = contents_response.json()
    findings = []

    for wf in workflow_files:
        download_url = wf.get('download_url')
        if not download_url:
            continue

        file_content = requests.get(download_url).text

        for pattern in SEARCH_PATTERNS:
            if pattern.lower() in file_content.lower():
                findings.append(pattern)

    findings = list(set(findings))

    recommendations = []
    complexities = []
    actions = []

    for finding in findings:
        if finding in REMEDIATION_MAP:
            recommendations.append(
                REMEDIATION_MAP[finding]["replacement"]
            )
            complexities.append(
                REMEDIATION_MAP[finding]["complexity"]
            )
            actions.append(
                REMEDIATION_MAP[finding]["action"]
            )

    results.append({
        "Repository": repo_name,
        "AWS_Usage_Found": "YES" if findings else "NO",
        "Patterns": ", ".join(findings),
        "Azure_Replacement": ", ".join(set(recommendations)),
        "Complexity": ", ".join(set(complexities)),
        "Suggested_Action": ", ".join(set(actions))
    })

with open('scan-report.csv', 'w', newline='') as csvfile:
    fieldnames = [
        'Repository',
        'AWS_Usage_Found',
        'Patterns',
        'Azure_Replacement',
        'Complexity',
        'Suggested_Action'
    ]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(results)

print("Report generated: scan-report.csv")
