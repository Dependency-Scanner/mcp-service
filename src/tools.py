import os
import requests

from datetime import datetime

def scan_repo_for_vulnerabilities(repo_url: str, github_pat: str, bearer_token: str):
    """
    Scans the given repository for dependency vulnerabilities using the ThreatLens API.

    Args:
        repo_url (str): The URL of the repository to scan.
        github_pat (str): GitHub Personal Access Token.
        bearer_token (str): Bearer token for API authentication.

    Returns:
        dict: On success, returns a dictionary with repository info and vulnerabilities:
            {
                "content_type": "application/json",
                "status": "success",
                "message": {
                    "repository": str,
                    "scan_time": str,
                    "status": str,
                    "total_count": int,
                    "vulnerabilities": list
                }
            }
        On error, returns:
            {
                "content_type": "application/json",
                "status": "error",
                "message": str  # error details
            }

    Raises:
        EnvironmentError: If the API URL is not set in environment variables.
    """
    base_api_url = os.getenv("THREATLENS_API_URL")
    if not base_api_url:
        raise EnvironmentError("THREATLENS_API_URL not set in environment variables.")
    api_url = f"{base_api_url}/internal/scan"

    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json"
    }
    payload = {
        "repo_url": repo_url,
        "github_pat": github_pat
    }

    try:
        response = requests.post(api_url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()

        # Example response formatting
        result = {
            "content_type": "application/json",
            "status": "success",
            "message": {
                "repository": data.get("repository", repo_url.split('/')[-2] + '/' + repo_url.split('/')[-1]),
                "scan_time": datetime.now().isoformat(),
                "status": data.get("status", "completed"),
                "total_count": len(data.get("vulnerabilities", [])),
                "vulnerabilities": data.get("vulnerabilities", [])
            }
        }
        return result
    except requests.RequestException as e:
        result = {
            "content_type": "application/json",
            "status": "error",
            "message": str(e)
        }
        return result