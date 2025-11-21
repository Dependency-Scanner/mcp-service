import asyncio
import os

from fastmcp import FastMCP
from config.logging_config import setup_logging
from src.tools import initialize_tool

# Setup logging
logger = setup_logging()

# Initialize the MCP server
mcp = FastMCP("Depemdency Scanner MCP Service")

if __name__ == "__main__":
    initialize_tool(mcp)
    logger.info(f" MCP server started on port {os.getenv('PORT', 8080)}")
    asyncio.run(
        mcp.run_async(
            transport="streamable-http", 
            host="0.0.0.0", 
            port=os.getenv("PORT", 8080),
        )
    )