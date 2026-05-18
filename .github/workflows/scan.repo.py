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

    results.append({
        "Repository": repo_name,
        "AWS_Usage_Found": "YES" if findings else "NO",
        "Patterns": ", ".join(findings)
    })

with open('scan-report.csv', 'w', newline='') as csvfile:
    fieldnames = ['Repository', 'AWS_Usage_Found', 'Patterns']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(results)

print("Report generated: scan-report.csv")
