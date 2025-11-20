from mcp.server.fastmcp import FastMCP

# Initialize the MCP server
mcp = FastMCP(
        name="Dependency ",
        host="127.0.0.1",
        port=9000,
        log_level="DEBUG"
    )

@mcp.tool()
def greet(name: str) -> str:
    """
    Returns a personalized greeting message.
    
    Args:
        name: The name of the person to greet.
    """
    return f"Hello, {name}! Your local MCP tool is working."

if __name__ == "__main__":
    # Runs the server using the default 'stdio' transport
    mcp.run()