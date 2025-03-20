# 🚀 Python MCP Server Template

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![MCP](https://img.shields.io/badge/MCP-Enabled-brightgreen.svg)
![Platform](https://img.shields.io/badge/Platform-Cursor%20|%20Windsurf%20|%20Cline-orange.svg)

**The fastest way to create Python-based MCP servers!**

</div>

## ✨ Why This Template?

- **⚡ Blazing Fast**: Build and run in seconds, not minutes
- **🔄 Multi-instance Friendly**: Run multiple Cursor windows on the same codebase without conflicts
- **🔌 Reliable Connections**: Stable connection handling compared to TypeScript alternatives
- **🛠️ Rapid Development**: Python implementation enables quick iterations and testing

## 🛑 TypeScript Server Challenges

When working with TypeScript-based MCP servers in multi-instance scenarios, numerous issues arise:

- **Port Conflicts**: TypeScript servers frequently conflict when multiple Cursor instances attempt to use the same ports
- **File Locking**: TypeScript build processes often lock files, preventing proper synchronization across instances
- **Resource Consumption**: TypeScript servers consume significantly more resources when running multiple instances
- **Compilation Delays**: Each TypeScript server instance triggers separate compilation processes, causing delays
- **Connection Instability**: Multiple TypeScript server instances compete for resources, leading to connection drops

This Python template eliminates these issues with its lightweight implementation, allowing seamless operation across multiple Cursor windows working on the same codebase simultaneously.

## 🔍 Context Reference

Take advantage of the example files in the `context` folder to enhance your MCP server implementation:

- **Deterministic Context**: Reference implementations that follow best practices
- **Example Patterns**: Common patterns for handling tools and client interactions
- **Ready-to-use Components**: Building blocks for creating robust MCP servers

Studying these context files will significantly accelerate your development process and help you build more reliable MCP servers.

## 🚦 Quick Setup

```bash
# 1. Install uv if you haven't already
pip install uv

# 2. Create virtual environment
uv venv

# 3. Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On Unix/macOS:
source .venv/bin/activate

# 4. Install dependencies
uv pip install -e .

# 5. Run the server
python main.py
```

## ⚙️ Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `--port` | Port to listen on | 8080 |
| `--transport` | Transport type (sse or stdio) | sse |

