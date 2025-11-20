import nest_asyncio
nest_asyncio.apply()

from llama_index.llms.ollama import Ollama
from llama_index.core import Settings

llm = Ollama(model="llama3.2", request_timeout=120.0)
Settings.llm = llm

from llama_index.tools.mcp import BasicMCPClient, McpToolSpec

mcp_client = BasicMCPClient("http://127.0.0.1:8000/sse")
mcp_tools = McpToolSpec(client=mcp_client)

tools = await mcp_tools.to_tool_list_async()
for tool in tools:
    print(tool.metadata.name, tool.metadata.description)
    
    SYSTEM_PROMPT = """\
You are an AI assistant for Tool Calling.

Before you help a user, you need to work with tools to interact with Our Database
"""

from llama_index.tools.mcp import McpToolSpec
from llama_index.core.agent.workflow import FunctionAgent

async def get_agent(tools: McpToolSpec):
    tools = await tools.to_tool_list_async()
    agent = FunctionAgent(
        name="Agent",
        description="An agent that can work with Our Database software.",
        tools=tools,
        llm=OpenAI(model="gpt-4"),
        system_prompt=SYSTEM_PROMPT,
    )
    return agent


from llama_index.core.agent.workflow import (
    FunctionAgent, 
    ToolCallResult, 
    ToolCall)

from llama_index.core.workflow import Context

async def handle_user_message(
    message_content: str,
    agent: FunctionAgent,
    agent_context: Context,
    verbose: bool = False,
):
    handler = agent.run(message_content, ctx=agent_context)
    async for event in handler.stream_events():
        if verbose and type(event) == ToolCall:
            print(f"Calling tool {event.tool_name} with kwargs {event.tool_kwargs}")
        elif verbose and type(event) == ToolCallResult:
            print(f"Tool {event.tool_name} returned {event.tool_output}")

    response = await handler
    return str(response)


from llama_index.tools.mcp import BasicMCPClient, McpToolSpec


mcp_client = BasicMCPClient("http://127.0.0.1:8000/sse")
mcp_tool = McpToolSpec(client=mcp_client)

# get the agent
agent = await get_agent(mcp_tool)

# create the agent context
agent_context = Context(agent)


# Run the agent!
while True:
    user_input = input("Enter your message: ")
    if user_input == "exit":
        break
    print("User: ", user_input)
    response = await handle_user_message(user_input, agent, agent_context, verbose=True)
    print("Agent: ", response)