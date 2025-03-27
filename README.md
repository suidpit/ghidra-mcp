# Ghidra MCP Server

This extension contains a Ghidra Plugin that exposes a Model Context Protocol (MCP) server to expose Ghidra functionalities.

It can be used by LLM agents to aid reverse engineer in the process of understanding complex binaries and save time.

Example usage on a simple crackme:

https://github.com/user-attachments/assets/ae938375-950a-4a29-bd48-165f856d970b

As you can see from the video, Claude 3.7 Sonnet at some point goes "extra mile mode" and decides to write a Ghidra Script to solve the crackme, so I had to intervene
and "steer" it towards KISS. I decided to keep that part since I think it clearly shows that, no matter how cool our MCP tools can be, LLMs are LLMs and there's so much more than
tooling – such as good prompting and guidance.

## Why?

MCP is the sexy thing these days, and [an excellent Ghidra MCP plugin](https://github.com/LaurieWired/GhidraMCP) has been already released a few days ago.

Nevertheless:

- Writing tools is fun
- Effectively using LLMs is not straightforward yet, and "owning" the tooling helps a lot
- I wanted to experiment with Java – it doesn't happen often – and embedding a Spring Boot application in Ghidra seemed an excellent way of doing that


Plus, quoting from the eternal "PoC || GTFO":

> Build Your Own Fucking Birdfeeder.
<img src=https://github.com/user-attachments/assets/60289fe9-429c-42a5-ad92-c17aa207ccdc width=50%>

## What?

[Model Context Protocol (MCP)](https://www.anthropic.com/news/model-context-protocol) was introduced in December 2024 by Anthropic to create a standard for interaction between
AI assistant and "data sources", or "tools". Building an MCP server basically means building new equipment for AI agents to use, and since it's a standard, it's interoperable
and we can use the same tools with different agents. That sounds great!

In its current status, this Ghidra MCP plugin exposes the following tools:

- List functions
- Decompile functions
- Rename functions
- Rename local variables
- Comment functions

It's mostly an experiment right now, but I'm eager to tinker with it and really understand how useful it can be for serious reverse engineering tasks.

## Installation

You can download the extension from the releases.

To install it, launch Ghidra and then, before selecting any Tool, select File -> Install Extension -> "+" button to add the downloaded ZIP file. Once in the Code Browser Tool, select File -> Configure, then Configure under "Developer", and make sure to check the "GhidraMCPPlugin" box.

This will start the MCP server (you can confirm there's a `java` process running on port 8888 in your machine).

## Build

Run `gradle` in the root of the project and you should see the ZIP file in the `dist` folder.

## Usage

The embedded MCP Server in Ghidra is configured with the "SSE" transport, therefore you will need an MCP client that supports SSE.

Alternatively, install `mcp-proxy` via `uv` (`uv tool install mcp-proxy`) so that you can use it to do STDIO<->SSE proxying.
For instance, this is my MCP server configuration in Cursor:

```json
{
    "mcpServers": {
      "GhidraMCP": {
        "command": "mcp-proxy",
        "args": ["http://localhost:8888/sse"]
      }
    }
  }
```

**Note**: when using `mcp-proxy`, make sure to start Ghidra and open the Code Browser before starting the MCP tool in your client, otherwise `mcp-proxy` will not be able to connect to the SSE endpoint. 
