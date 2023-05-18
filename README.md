# SecurityAI GitHub Action

This GitHub Action scans and proposes fixes for code issues in a pull request using a custom security analysis API.

## Inputs

- `GITHUB_TOKEN`: Required. The GitHub token used for making API requests and creating comments on the pull request. You can use a Personal Access Token (PAT) with `repo` scope for private repositories.
- `BASE_URL`: Required. The base URL of the custom security analysis API.
- `PR_NUMBER`: Required. The number of the pull request to be analyzed.
- `THRESHOLD`: Optional. The minimum severity level for reporting issues. Default is "Low". Available values are "Low", "Medium", "High", and "Critical".

## Usage

To use this action in your workflow, follow these steps:

1. Create a new workflow file in your repository (e.g., `.github/workflows/scan_and_fix.yml`).

2. Add the following configuration to the workflow file:

```yaml
name: Code Scan and Fix

on:
  pull_request:
    branches:
      - '*'  # Trigger on pull requests for any branch

jobs:
  scan_and_fix:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v2
      with:
        token: ${{ secrets.ORG_ACTIONS_PAT }} # Use the PAT for checking out the code

    - name: Run Scan and Fix
      uses: security-autopilot/securityai-github-action@main
      with:
        GITHUB_TOKEN: ${{ secrets.ORG_ACTIONS_PAT }} # Use the PAT for running the action
        THRESHOLD: 'Medium'