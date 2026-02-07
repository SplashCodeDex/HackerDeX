# Tech Stack - HackerDeX

## Core Language & Runtime
- **Python 3.10+:** The primary programming language for both CLI and Web back-ends, chosen for its vast library ecosystem and suitability for security automation.

## CLI Frameworks
- **Rich:** Used for creating a sophisticated, high-performance terminal UI with advanced formatting, tables, and interactive prompts.
- **Subprocess Orchestration:** The core mechanism for interacting with the 55+ external security tools, utilizing `subprocess.run` and `Popen` for thread-safe, asynchronous execution capable of handling diverse tool behaviors.

## Web Stack
- **Flask:** The primary web framework for serving the management UI and API.
- **Flask-SocketIO & Eventlet:** Provides real-time, bi-directional communication between the tool execution engine and the web dashboard, enabling live output streaming for all 55+ supported tools.
- **HTML5/CSS3/JS:** Frontend technologies for the interactive dashboard.

## AI & Intelligence
- **Google Gemini (google-genai):** Integrated via the official Python SDK to provide automated vulnerability analysis, summary generation, and exploit verification scripting, scaling across the outputs of the entire tool catalog.

## Infrastructure & Deployment
- **Docker:** Provides a consistent, isolated environment ensuring that all 55+ tools and their complex dependencies (which vary widely) run correctly across different host systems without conflict.
- **Docker Compose:** Orchestrates the multi-container environment (HackerDeX app and potential external services like database listeners).

## Data Management
- **VulnStore:** A custom internal data architecture designed to normalize, persist, and correlate intelligence gathered from the disparate outputs of over 55 different security tools.
