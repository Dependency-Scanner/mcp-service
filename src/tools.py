import os
import requests

from datetime import datetime
from config.logging_config import setup_logging

# Setup logging
logger = setup_logging()

def initialize_tool(mcp):
    logger.info("Initializing Dependency Scanner Tools...")
    # mcp.tool(name="Dependency Scanner Tool")(scan_repo_for_vulnerabilities)
    # mcp.tool(name="Health Check Tool")(health_check)
    # mcp.tool(name="Auth Service Dependency Scanner Tool")(scan_dependencies_with_auth_service)
    mcp.tool(name="Addition Tool")(add)
    mcp.tool(name="Subtraction Tool")(subtract)

# async def scan_repo_for_vulnerabilities(repo_url: str, github_pat: str, bearer_token: str):
#     """
#     Scans the given repository for dependency vulnerabilities using the ThreatLens API.

#     Args:
#         repo_url (str): The URL of the repository to scan.
#         github_pat (str): GitHub Personal Access Token.
#         bearer_token (str): Bearer token for API authentication.

#     Returns:
#         dict: On success, returns a dictionary with repository info and vulnerabilities:
#             {
#                 "content_type": "application/json",
#                 "status": "success",
#                 "message": {
#                     "repository": str,
#                     "scan_time": str,
#                     "status": str,
#                     "total_count": int,
#                     "vulnerabilities": list
#                 }
#             }
#         On error, returns:
#             {
#                 "content_type": "application/json",
#                 "status": "error",
#                 "message": str  # error details
#             }

#     Raises:
#         EnvironmentError: If the API URL is not set in environment variables.
#     """
#     base_api_url = os.getenv("DEPENDENCY_SCANNER_SERVICE_URL")
#     if not base_api_url:
#         raise EnvironmentError("THREATLENS_API_URL not set in environment variables.")
#     api_url = f"{base_api_url}/internal/scan"

#     headers = {
#         "Authorization": f"Bearer {bearer_token}",
#         "Content-Type": "application/json"
#     }
#     payload = {
#         "repo_url": repo_url,
#         "github_pat": github_pat
#     }

#     try:
#         response = requests.post(api_url, json=payload, headers=headers)
#         response.raise_for_status()
#         data = response.json()

#         # Example response formatting
#         result = {
#             "content_type": "application/json",
#             "status": "success",
#             "message": {
#                 "repository": data.get("repository", repo_url.split('/')[-2] + '/' + repo_url.split('/')[-1]),
#                 "scan_time": datetime.now().isoformat(),
#                 "status": data.get("status", "completed"),
#                 "total_count": len(data.get("vulnerabilities", [])),
#                 "vulnerabilities": data.get("vulnerabilities", [])
#             }
#         }
#         return result
#     except requests.RequestException as e:
#         result = {
#             "content_type": "application/json",
#             "status": "error",
#             "message": str(e)
#         }
#         return result
    
# async def health_check():
#     """
#     Performs a health check on the ThreatLens API.

#     Returns:
#         dict: {
#             "status": "success" if API is healthy,
#         }
#         If not healthy:
#         {
#             "status": "error",
#             "message": <error_message>
#         }
#     """
#     base_api_url = os.getenv("DEPENDENCY_SCANNER_SERVICE_URL")
#     if not base_api_url:
#         return {
#             "content_type": "application/json",
#             "status": "error",
#             "message": "THREATLENS_API_URL not set in environment variables."
#         }
#     health_url = f"{base_api_url}/health"

#     try:
#         response = requests.get(health_url)
#         if response.status_code == 200:
#             return {
#                 "content_type": "application/json",
#                 "status": "success",
#                 "message": "THREATLENS API is healthy."
                
#                 }
#         else:
#             return {"status": "error", "code": response.status_code, "message": response.text}
#     except requests.RequestException as e:
#         return {
#             "content_type": "application/json",
#             "status": "error",
#             "message": str(e)
#         }

# async def scan_dependencies_with_auth_service(repo_url: str, github_pat: str, assignee: str, dry_run: bool, bearer_token: str):
#     """
#     Scans the repository for dependency vulnerabilities using the AUTH_SERVICE_URL /api/v1/scan endpoint.

#     This endpoint:
#     - Clones the repository
#     - Detects all dependency files (package.json, requirements.txt, go.mod, pom.xml, build.gradle, Gemfile, etc.)
#     - Scans dependencies for known vulnerabilities
#     - Returns a list of vulnerabilities found

#     Args:
#         repo_url (str): The URL of the repository to scan.
#         github_pat (str): GitHub Personal Access Token.
#         assignee (str): User to assign vulnerabilities to.
#         dry_run (bool): If True, performs a dry run.
#         bearer_token (str): Bearer token for API authentication.

#     Returns:
#         dict: If response is 200, returns:
#             {
#                 "repository": str,
#                 "scan_time": str,
#                 "status": str,
#                 "total_count": int,
#                 "vulnerabilities": list
#             }
#         If response is 422 (validation error), returns:
#             {
#                 "status": "error",
#                 "code": 422,
#                 "message": str
#             }
#         For other errors, returns:
#             {
#                 "status": "error",
#                 "code": int,
#                 "message": str
#             }

#     Raises:
#         EnvironmentError: If the AUTH_SERVICE_URL is not set in environment variables.
#     """
#     base_api_url = os.getenv("AUTH_SERVICE_URL")
#     if not base_api_url:
#         raise EnvironmentError("AUTH_SERVICE_URL not set in environment variables.")
#     api_url = f"{base_api_url}/api/v1/scan"

#     headers = {
#         "Authorization": f"Bearer {bearer_token}",
#         "Content-Type": "application/json"
#     }
#     payload = {
#         "repo_url": repo_url,
#         "github_pat": github_pat,
#         "assignee": assignee,
#         "dry_run": dry_run
#     }

#     try:
#         response = requests.post(api_url, json=payload, headers=headers)
#         if response.status_code == 200:
#             return response.json()
#         elif response.status_code == 422:
#             return {
#                 "status": "error",
#                 "code": 422,
#                 "message": response.text
#             }
#         else:
#             return {
#                 "status": "error",
#                 "code": response.status_code,
#                 "message": response.text
#             }
#     except requests.RequestException as e:
#         return {
#             "status": "error",
#             "code": 500,
#             "message": str(e)
#         }

async def add(a: int, b: int) -> int:
    """Use this to add two numbers together.
    
    Args:
        a: The first number.
        b: The second number.
    
    Returns:
        The sum of the two numbers.
    """
    logger.info(f">>> Tool: 'add' called with numbers '{a}' and '{b}'")
    return a + b

async def subtract(a: int, b: int) -> int:
    """Use this to subtract two numbers.
    
    Args:
        a: The first number.
        b: The second number.
    
    Returns:
        The difference of the two numbers.
    """
    logger.info(f">>> Tool: 'subtract' called with numbers '{a}' and '{b}'")
    return a - b