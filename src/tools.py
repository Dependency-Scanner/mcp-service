import requests

from datetime import datetime
from config.logging_config import setup_logging

# Setup logging
logger = setup_logging()

API_BASE_URL = "http://localhost:8000"

def initialize_tool(mcp):
    logger.info("Initializing Dependency Scanner Tools...")
    mcp.tool(name="Scan for Vulnerabilities")(scan_for_vulnerabilities)

async def scan_for_vulnerabilities(repo_url: str, github_pat: str, assignee: str, dry_run: bool):
    """
    Scans the repository for dependency vulnerabilities using the AUTH_SERVICE_URL /api/v1/scan endpoint.

    This endpoint:
    - Clones the repository
    - Detects all dependency files (package.json, requirements.txt, go.mod, pom.xml, build.gradle, Gemfile, etc.)
    - Scans dependencies for known vulnerabilities
    - Returns a list of vulnerabilities found

    Args:
        repo_url (str): The URL of the repository to scan.
        github_pat (str): GitHub Personal Access Token.
        assignee (str): User to assign vulnerabilities to.
        dry_run (bool): If True, performs a dry run.

    Returns:
        dict: If response is 200, returns:
            {
                "repository": str,
                "scan_time": str,
                "status": str,
                "total_count": int,
                "vulnerabilities": [
                    {
                        "current_version": str,         # version in repo
                        "cve": str,                     # CVE identifier    
                        "cvs_score": float,             # CVSS score
                        "description": str,             # description of vulnerability
                        "file_path": str,               # path to dependency file
                        "package_manager": str,         # e.g., npm, pip, maven
                        "package_name": str,            # name of the package
                        "safe_version": str,            # version with fix
                        "severity": str                 # e.g., low, medium, high, critical
                    },
                    ...
                ]
            }
        If response is 422 (validation error), returns:
            {
                "status": "error",
                "code": 422,
                "message": str
            }
        For other errors, returns:
            {
                "status": "error",
                "code": int,
                "message": str
            }

    Raises:
        EnvironmentError: If the AUTH_SERVICE_URL is not set in environment variables.
    """
    api_url = f"{API_BASE_URL}/api/v1/scan"

    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "repo_url": repo_url,
        "github_pat": github_pat,
        "assignee": assignee,
        "dry_run": dry_run
    }

    logger.info(f"Sending vulnerability scan request to {api_url} for repo: {repo_url}")
    try:
        response = requests.post(api_url, json=payload, headers=headers)
        logger.info(f"Received response with status code: {response.status_code}")
        if response.status_code == 200:
            logger.info(f"Scan successful for repo: {repo_url}")
            return response.json()
        elif response.status_code == 422:
            logger.warning(f"Validation error for repo: {repo_url} - {response.text}")
            return {
                "status": "error",
                "code": 422,
                "message": response.text
            }
        else:
            logger.error(f"Unexpected error for repo: {repo_url} - {response.status_code}: {response.text}")
            return {
                "status": "error",
                "code": response.status_code,
                "message": response.text
            }
    except requests.RequestException as e:
        logger.error(f"RequestException during scan for repo: {repo_url} - {str(e)}")
        return {
            "status": "error",
            "code": 500,
            "message": str(e)
        }