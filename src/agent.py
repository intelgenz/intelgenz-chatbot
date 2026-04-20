import os
from typing import Annotated
from typing_extensions import TypedDict

from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, SystemMessage
from langchain_openai import AzureChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

from src.tools import (
    cve_id_lookup_tool,
    domain_lookup_tool,
    hash_lookup_tool,
    ip_address_lookup_tool,
    url_lookup_tool,
)


class State(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]


SYSTEM_PROMPT = """
You are a cybersecurity intelligence assistant. Answer only questions related to CVE IDs, IP addresses, domains, URLs, and file hashes.

If the user's question is not related to CVE, IP, domain, URL, or hash intelligence, reply exactly: "Please ask questions related to CVE, IP, domain, URL, or hash analysis. Please keep your queries focused on these topics for better assistance."

Use the available tools as follows:
- CVE IDs: cve_id_lookup_tool. Include CVE ID, description, CWE, CVSS score, attack vector, attack complexity, privileges required, user interaction, scope, confidentiality impact, integrity impact, availability impact, affected products, publication date, last modified date, references, exploit details if available, KEV status if available, zero-day indicator if available, and recommendations or patch details if available.
- Public IP addresses: ip_address_lookup_tool.
- Domains: domain_lookup_tool.
- URLs: url_lookup_tool.
- File hashes: hash_lookup_tool.

If one user message contains multiple indicators, call every relevant tool one by one and combine the results.
If a submitted IP address, domain, URL, CVE ID, or hash is malformed, try to correct obvious formatting issues. If it still cannot be corrected, briefly explain the correct format in 2 to 3 lines.
If the submitted IP address is private, respond with: "The given IP Address {address} is a private IP address. Please provide a public IP address for further analysis."
If the message contains non-English words, reply with: "Currently, only English is supported. Please continue your message in English."

For longer answers, use markdown with medium-sized headings and clear bullet points. Do not use tables.
For short validation or unsupported-topic answers, keep the answer to 1 to 3 lines.

Every answer must end with:
Confidence Score: <0-100>%
Source: <source>

Allowed sources are only:
- NVD for CVE answers
- VirusTotal for IP, domain, URL, or hash answers
- NVD, VirusTotal for mixed CVE and OSINT answers
- NA for unsupported questions, non-English questions, private IP responses, invalid-format responses, or missing configuration responses
Do not cite any other source.
""".strip()


tools = [
    cve_id_lookup_tool,
    ip_address_lookup_tool,
    domain_lookup_tool,
    url_lookup_tool,
    hash_lookup_tool,
]


llm_with_tools = None
graph = None


def _missing_azure_settings() -> list[str]:
    required_settings = [
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_DEPLOYMENT_NAME",
    ]
    return [setting for setting in required_settings if not os.getenv(setting)]


def get_llm_with_tools():
    global llm_with_tools
    if llm_with_tools is None:
        missing_settings = _missing_azure_settings()
        if missing_settings:
            missing = ", ".join(missing_settings)
            raise RuntimeError(f"Missing required Azure OpenAI environment variables: {missing}")
        llm = AzureChatOpenAI(
            azure_deployment=os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME", ""),
            azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT", ""),
            api_key=os.getenv("AZURE_OPENAI_API_KEY", ""),
            api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-10-21"),
            temperature=0,
            max_tokens=int(os.getenv("AZURE_OPENAI_MAX_TOKENS", "10000")),
        )
        llm_with_tools = llm.bind_tools(tools)
    return llm_with_tools


async def tool_calling_llm(state: State) -> dict[str, list[AnyMessage]]:
    response = await get_llm_with_tools().ainvoke([SystemMessage(content=SYSTEM_PROMPT), *state["messages"]])
    return {"messages": [response]}


def build_graph(memory: MemorySaver | None = None):
    builder = StateGraph(State)
    builder.add_node("tool_calling_llm", tool_calling_llm)
    builder.add_node("tools", ToolNode(tools))
    builder.add_edge(START, "tool_calling_llm")
    builder.add_conditional_edges("tool_calling_llm", tools_condition)
    builder.add_edge("tools", "tool_calling_llm")
    return builder.compile(checkpointer=memory or MemorySaver())


def get_graph():
    global graph
    if graph is None:
        graph = build_graph()
    return graph


async def ask_agent(message: str, session_id: str) -> str:
    active_graph = get_graph()
    try:
        result = await active_graph.ainvoke(
            {"messages": [HumanMessage(content=message)]},
            config={"configurable": {"thread_id": session_id}},
        )
    except RuntimeError as exc:
        return f"{exc}\nConfidence Score: 100%\nSource: NA"
    final_message = result["messages"][-1]
    if isinstance(final_message, AIMessage):
        return str(final_message.content)
    return str(final_message.content)
