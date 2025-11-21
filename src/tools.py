import requests

from datetime import datetime
from config.logging_config import setup_logging

# Setup logging
logger = setup_logging()

API_BASE_URL = "http://localhost:8000"

def initialize_tool(mcp):
    logger.info("Initializing Dependency Scanner Tools...")
    mcp.tool(name="Scan for Vulnerabilities")(scan_for_vulnerabilities)
    mcp.tool(name="Scan and Fix Vulnerabilities")(scan_and_fix_vulnerabilities)
    mcp.tool(name="Get Scan and Fix Job Status")(get_scan_and_fix_job_status)
    mcp.tool(name="Delete Scan and Fix Job")(delete_scan_and_fix_job)
    mcp.tool(name="List Scan and Fix Jobs")(list_scan_and_fix_jobs)
    mcp.tool(name="Health Check")(health_check)
    mcp.tool(name="Service Status")(service_status)

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
        
async def scan_and_fix_vulnerabilities(
    repo_url: str,
    github_pat: str,
    jira_server_url: str,
    jira_pat: str,
    jira_project_id: str,
    jira_assignee_id: str,
    jira_reporter_id: str,
    jira_custom_fields: dict,
    assignee: str,
    dry_run: bool
):
    """
    Scans the repository for vulnerable dependencies and attempts to automatically fix them.

    This endpoint:
    - Scans the repository for vulnerable dependencies.
    - Deduplicates and groups vulnerabilities by package.
    - Creates JIRA tickets for each vulnerable package.
    - Creates GitHub pull requests to update dependencies to safe versions.
    - Adds comments to JIRA tickets with links to the corresponding pull requests.

    Args:
        repo_url (str): The URL of the repository to scan.
        github_pat (str): GitHub Personal Access Token.
        jira_server_url (str): The base URL of the JIRA server.
        jira_pat (str): JIRA Personal Access Token.
        jira_project_id (str): JIRA project key or ID.
        jira_assignee_id (str): JIRA user ID to assign tickets.
        jira_reporter_id (str): JIRA user ID to report tickets.
        jira_custom_fields (dict): Custom fields for JIRA ticket creation.
        assignee (str): User to assign vulnerabilities to.
        dry_run (bool): If True, performs a dry run without making changes.

    Returns:
        dict: If response is 202, returns:
            {
                "job_id": str,
                "message": str,
                "status": str,
                "status_url": str,
                "repository": str,
                "scan_time": str,
                "total_found": int,
                "total_processed": int,
                "total_skipped": int,
                "processing_time": str,
                "vulnerabilities": [
                    {
                        "package_name": str,
                        "severity": str,
                        "cve": str,
                        "jira_ticket": str,
                        "pull_request_url": str,
                        "status": str
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

    Note:
        This is an asynchronous operation. Use the returned 'job_id' to track progress via /api/v1/jobs/{job_id}.
    """
    api_url = f"{API_BASE_URL}/api/v1/scan-and-fix"
    headers = {
        "Content-Type": "application/json"
    }
    payload = {
        "repo_url": repo_url,
        "github_pat": github_pat,
        "jira_server_url": jira_server_url,
        "jira_pat": jira_pat,
        "jira_project_id": jira_project_id,
        "jira_assignee_id": jira_assignee_id,
        "jira_reporter_id": jira_reporter_id,
        "jira_custom_fields": jira_custom_fields,
        "assignee": assignee,
        "dry_run": dry_run
    }

    logger.info(f"Sending scan-and-fix request to {api_url} for repo: {repo_url}")
    try:
        response = requests.post(api_url, json=payload, headers=headers)
        logger.info(f"Received response with status code: {response.status_code}")
        if response.status_code == 202:
            logger.info(f"Scan and fix job started for repo: {repo_url}")
            return response.json()
        elif response.status_code == 422:
            logger.warning(f"Validation error for scan-and-fix: {response.text}")
            return {
                "status": "error",
                "code": 422,
                "message": response.text
            }
        else:
            logger.error(f"Unexpected error for scan-and-fix: {response.status_code}: {response.text}")
            return {
                "status": "error",
                "code": response.status_code,
                "message": response.text
            }
    except requests.RequestException as e:
        logger.error(f"RequestException during scan-and-fix for repo: {repo_url} - {str(e)}")
        return {
            "status": "error",
            "code": 500,
            "message": str(e)
        }
        
async def get_scan_and_fix_job_status(job_id: str):
    """
    Gets the current status and results of a scan-and-fix job.

    Args:
        job_id (str): The job ID to query.

    Returns:
        dict: If response is 200, returns job status and results:
            {
                "id": str,
                "status": str,
                "repo_url": str,
                "created_at": str,
                "started_at": str,
                "completed_at": str,
                "result": dict
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
    """
    api_url = f"{API_BASE_URL}/api/v1/jobs/{job_id}"
    headers = {
        "Accept": "application/json"
    }

    logger.info(f"Fetching scan-and-fix job status from {api_url}")
    try:
        response = requests.get(api_url, headers=headers)
        logger.info(f"Received response with status code: {response.status_code}")
        if response.status_code == 200:
            logger.info(f"Job status fetched successfully for job_id: {job_id}")
            return response.json()
        elif response.status_code == 422:
            logger.warning(f"Validation error for job status: {response.text}")
            return {
                "status": "error",
                "code": 422,
                "message": response.text
            }
        else:
            logger.error(f"Unexpected error for job status: {response.status_code}: {response.text}")
            return {
                "status": "error",
                "code": response.status_code,
                "message": response.text
            }
    except requests.RequestException as e:
        logger.error(f"RequestException during job status fetch for job_id: {job_id} - {str(e)}")
        return {
            "status": "error",
            "code": 500,
            "message": str(e)
        }
        
async def delete_scan_and_fix_job(job_id: str):
    """
    Deletes a scan-and-fix job by job ID.

    Args:
        job_id (str): The job ID to delete.

    Returns:
        dict: If response is 204, returns success message.
        If response is 422 (validation error), returns error details.
        For other errors, returns error details.
    """
    api_url = f"{API_BASE_URL}/api/v1/jobs/{job_id}"
    headers = {
        "Accept": "application/json"
    }

    logger.info(f"Deleting scan-and-fix job at {api_url}")
    try:
        response = requests.delete(api_url, headers=headers)
        logger.info(f"Received response with status code: {response.status_code}")
        if response.status_code == 204:
            logger.info(f"Job deleted successfully for job_id: {job_id}")
            return {
                "status": "success",
                "code": 204,
                "message": f"Job {job_id} deleted successfully."
            }
        elif response.status_code == 422:
            logger.warning(f"Validation error for job delete: {response.text}")
            return {
                "status": "error",
                "code": 422,
                "message": response.text
            }
        else:
            logger.error(f"Unexpected error for job delete: {response.status_code}: {response.text}")
            return {
                "status": "error",
                "code": response.status_code,
                "message": response.text
            }
    except requests.RequestException as e:
        logger.error(f"RequestException during job delete for job_id: {job_id} - {str(e)}")
        return {
            "status": "error",
            "code": 500,
            "message": str(e)
        }
        
async def list_scan_and_fix_jobs(page: int = 1, limit: int = 10, status: str = "", repo_url: str = ""):
    """
    Lists all scan-and-fix jobs with pagination support.

    Args:
        page (int): Page number (default: 1).
        limit (int): Number of jobs per page (default: 10, max: 100).
        status (str, optional): Filter jobs by status.
        repo_url (str, optional): Filter jobs by repository URL.

    Returns:
        dict: If response is 200, returns:
            {
                "jobs": [
                    {
                        "id": str,
                        "repo_url": str,
                        "status": str,
                        "created_at": str,
                        "completed_at": str
                    },
                    ...
                ],
                "pagination": {
                    "page": int,
                    "limit": int,
                    "total": int,
                    "total_pages": int
                }
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
    """
    api_url = f"{API_BASE_URL}/api/v1/jobs"
    headers = {
        "Accept": "application/json"
    }
    params = {
        "page": page,
        "limit": limit,
        "status": "",
        "repo_url": ""
    }
    if status:
        params["status"] = status
    if repo_url:
        params["repo_url"] = repo_url

    logger.info(f"Listing scan-and-fix jobs from {api_url} with params: {params}")
    try:
        response = requests.get(api_url, headers=headers, params=params)
        logger.info(f"Received response with status code: {response.status_code}")
        if response.status_code == 200:
            logger.info("Jobs listed successfully.")
            return response.json()
        elif response.status_code == 422:
            logger.warning(f"Validation error for job listing: {response.text}")
            return {
                "status": "error",
                "code": 422,
                "message": response.text
            }
        else:
            logger.error(f"Unexpected error for job listing: {response.status_code}: {response.text}")
            return {
                "status": "error",
                "code": response.status_code,
                "message": response.text
            }
    except requests.RequestException as e:
        logger.error(f"RequestException during job listing - {str(e)}")
        return {
            "status": "error",
            "code": 500,
            "message": str(e)
        }
        
async def health_check():
    """
    Checks if the service is healthy and running.

    Returns:
        dict: If response is 200, returns:
            {
                "status": str,
                "version": str,
                "timestamp": str
            }
        For other errors, returns:
            {
                "status": "error",
                "code": int,
                "message": str
            }
    """
    api_url = f"{API_BASE_URL}/health"
    headers = {
        "Accept": "application/json"
    }

    logger.info(f"Performing health check at {api_url}")
    try:
        response = requests.get(api_url, headers=headers)
        logger.info(f"Received response with status code: {response.status_code}")
        if response.status_code == 200:
            logger.info("Service health check successful.")
            return response.json()
        else:
            logger.error(f"Health check failed: {response.status_code}: {response.text}")
            return {
                "status": "error",
                "code": response.status_code,
                "message": response.text
            }
    except requests.RequestException as e:
        logger.error(f"RequestException during health check - {str(e)}")
        return {
            "status": "error",
            "code": 500,
            "message": str(e)
        }

async def service_status():
    """
    Gets detailed service status including uptime and dependencies.

    Returns:
        dict: If response is 200, returns:
            {
                "service": str,
                "status": str,
                "version": str,
                "uptime": str,
                "services": dict
            }
        For other errors, returns:
            {
                "status": "error",
                "code": int,
                "message": str
            }
    """
    api_url = f"{API_BASE_URL}/status"
    headers = {
        "Accept": "application/json"
    }

    logger.info(f"Fetching service status from {api_url}")
    try:
        response = requests.get(api_url, headers=headers)
        logger.info(f"Received response with status code: {response.status_code}")
        if response.status_code == 200:
            logger.info("Service status fetched successfully.")
            return response.json()
        else:
            logger.error(f"Service status failed: {response.status_code}: {response.text}")
            return {
                "status": "error",
                "code": response.status_code,
                "message": response.text
            }
    except requests.RequestException as e:
        logger.error(f"RequestException during service status fetch - {str(e)}")
        return {
            "status": "error",
            "code": 500,
            "message": str(e)
        }