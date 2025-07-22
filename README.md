## 🔐 What is VulnSage?

**VulnSage** is a powerful LLM Agent designed to automate source code vulnerability detection. By leveraging Google's **Vertex AI (Gemini)** and **LangChain**, it mimics the behavior of a security expert: parsing code structure, tracking data flow, identifying risky sink calls, and providing human-readable explanations and fix suggestions.

Unlike traditional static analyzers or black-box classifiers, VulnSage orchestrates multiple tools (AST analysis, taint tracing, LLM reasoning) through a **modular Agent architecture**, allowing flexible extension and deep code understanding.

---

## ⚙️ Key Features

- 🔍 Detects vulnerabilities via AST, taint flow, and LLM reasoning
- 🧠 Uses Google Gemini models via Vertex AI with secure IAM auth
- 🛠️ Modular tools: easily add custom analyzers or ML classifiers
- 🗣️ Natural language interface + explanation for each finding
- 📦 Works as CLI, API, or web app (e.g., FastAPI, Gradio)

---
**VulnSage aims to bridge that gap.**  
By combining LLMs with structured analysis tools, VulnSage is designed to act like a junior security analyst that not only finds bugs, but understands how they propagate, explains why they're dangerous, and suggests possible fixes.

I built VulnSage to explore what’s possible when we bring **Agent architecture** to **offensive security** — especially in early stages like red teaming, source review, and exploit discovery.

---

## 🤝 Feedback Welcome

VulnSage is still in its early phase, and your feedback is critical.  
If you’re a red teamer, researcher, bug hunter, or LLM enthusiast — your perspective can help make this tool better.

- 🐞 Found a bug or false positive? File an issue
- 💡 Have ideas to improve taint tracking or explanation? Suggest a PR
- 📚 Do you want to talk? Let’s talk! Email:stark.lee147@gmail.com

Together, we can build a better generation of **AI-powered offensive security agents**.

