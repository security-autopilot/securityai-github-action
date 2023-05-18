import os
import requests
from github import Github
import difflib
import argparse
import re
from json import JSONDecodeError, dumps, loads


parser = argparse.ArgumentParser()
parser.add_argument("--github_token", required=True)
parser.add_argument("--repo_name", required=True)
parser.add_argument("--base_url", required=True)
parser.add_argument("--pr_number", required=True, type=int)
parser.add_argument("--threshold", required=True)

args = parser.parse_args()

GITHUB_TOKEN = args.github_token
REPO_NAME = args.repo_name

github = Github(GITHUB_TOKEN)
repo = github.get_repo(REPO_NAME)
pull_request = repo.get_pull(args.pr_number)
files = pull_request.get_files()

# Convert the threshold argument to a numerical value for comparison
severity_values = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
threshold_value = severity_values[args.threshold]


vulnerabilities_above_threshold = []

total_vulnerabilities = 0

fail_from_error = False


def extract_added_lines(patch):
    added_lines = []
    for line in patch.split("\n"):
        if line.startswith("+") and not line.startswith("+++"):
            added_lines.append(line[1:])
    return "\n".join(added_lines)


def handle_error(error_message, response=None, error=None):
    print(error_message)
    if response is not None:
        print(f"Response content: {response.content}")
    if error:
        print(f"Error: {error}")
    pull_request.create_issue_comment(error_message)


for file in files:
    print(f"scanning file {file.filename}")
    added_lines = extract_added_lines(file.patch)
    response = requests.post(
        f"{args.base_url}/scan",
        json={"source_code": added_lines},
    )

    try:
        scan_response = loads(dumps(response.text))
    except JSONDecodeError:
        error_message = f"Security Autopilot: Unable to parse JSON response from the server for file {file.filename} response {response}."
        handle_error(error_message, response)
        fail_from_error = True
        continue

    try:
        vulnerabilities = scan_response["data"]["analysis"]
        for vulnerability_analysis in vulnerabilities:
            vulnerability_list = loads(
                vulnerability_analysis["response"]
            )  # hack, the response here should be a dict. API returns a string bug.

            for vulnerability in vulnerability_list:
                if (
                    severity_values.get(vulnerability["severity"], 0)
                    > severity_values[args.threshold]
                ):
                    vulnerabilities_above_threshold.append(vulnerability)

                total_vulnerabilities += 1

    except Exception as e:
        error_message = f"Security Autopilot: Unable to process the data from {file.filename} and response {scan_response}."
        handle_error(error_message, error=e)
        fail_from_error = True
        continue

if len(vulnerabilities_above_threshold) > 0:
    comment = f"Security Autopilot: Vulnerabilities above threshold found: {vulnerabilities_above_threshold}\n\n"
    for vulnerability in vulnerabilities_above_threshold:
        comment += f"- {vulnerability['title']} - {vulnerability['description']}\n"

    handle_error(comment)

fixes = 0
for file in files:
    print(f"Security Autopilot: Determining potential fixes for file {file.filename}")
    response = requests.post(
        f"{args.base_url}/fix",
        json={"source_code": file.patch},
    )

    try:
        fix_response = loads(dumps(response.text))
    except JSONDecodeError:
        error_message = f"Security Autopilot: Unable to parse JSON response from the server for file {file.filename} response {response}."
        handle_error(error_message, response)
        fail_from_error = True
        continue

    try:
        for analysis in fix_response["data"]["analysis"]:
            original_code = analysis["chunk"]
            fixed_code = analysis["response"]
            line_number = analysis.get("line_number", None)

            diff = difflib.unified_diff(
                original_code.splitlines(), fixed_code.splitlines(), lineterm=""
            )
            diff_text = "\n".join(list(diff))

            suggestion = (
                f"Security Autopilot: Suggested fix:\n``` suggestion\n{diff_text}\n ```"
            )
            if line_number:
                # Create a review comment with a suggestion at the specified line number
                repo.create_pull_review_comment(
                    pull_request.number,
                    suggestion,
                    file.sha,
                    file.filename,
                    line_number,
                )
                print(suggestion)
            else:
                # Create a regular issue comment in the PR
                handle_error(suggestion)
            fixes += 1
    except Exception as e:
        error_message = f"Security Autopilot: Unable to parse JSON response from the server for file {file.filename} response {fix_response}."
        handle_error(error_message, error=e)
        fail_from_error = True
        continue

print(
    f"Security Autopilot: Finished scanning and fixing. {'No' if total_vulnerabilities == 0 else total_vulnerabilities} total vulnerabilities detected. A total of {fixes} fixes were suggested."
)

if len(vulnerabilities_above_threshold) > 0:
    raise Exception(
        "Security Autopilot: At least one vulnerability with severity greater than the threshold was detected."
    )
if fail_from_error:
    raise Exception("Security Autopilot: An error occurred while scanning or fixing.")
