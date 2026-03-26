# 🛡️ LLM Security Firewall (Proxy Gateway)

A real-time, multi-layered semantic filtering proxy designed to protect black-box Large Language Models (LLMs) from prompt injections, jailbreaks, and data leakage. 

Built for the **[Insert Hackathon Name]**, this middleware intercepts incoming LLM requests, evaluates them across three security layers, and ensures only safe, benign prompts reach the underlying model.

## 🚀 The Problem & Our Solution
As LLMs become integrated into production environments, they remain highly vulnerable to adversarial attacks (e.g., "DAN" prompts, system prompt extraction). 

**Our Solution:** We built a standalone HTTP proxy gateway that sits between the user and the LLM. By decoupling security from the main application, we achieve a defense-in-depth strategy without modifying the underlying LLM. Furthermore, our proxy includes **Protocol Translation**, allowing it to accept industry-standard OpenAI-formatted requests, translate them to Google Gemini 2.5 Flash for high-speed processing, and seamlessly translate the response back.

## 🧠 Architecture & Security Layers

### 1. Ingress Filtering (Input Defense)
* **Layer 1: Heuristic & Regex Scanning (Lightning Fast):** Instantly blocks hardcoded attack signatures and known jailbreak phrases.
* **Layer 2: Semantic Vector Search (Fast):** Designed to catch semantic similarities to known attacks.
* **Layer 3: LLM-as-a-Judge (Moderate):** Designed to route complex prompts to a specialized, smaller security model for deep contextual analysis.

### 2. Egress Filtering (Output Defense)
* Scans the generated response from the LLM before returning it to the user. If the LLM was successfully tricked into leaking its system prompt or generating unsafe code, the proxy catches the anomaly, scrubs the response, and returns a `403 Security Exception`.

## 🛠️ Tech Stack
* **Framework:** Python, FastAPI (Asynchronous, low-latency API)
* **Target LLM:** Google Gemini 2.5 Flash (via Protocol Translation)

---

## 🚦 Quick Start Guide

### Prerequisites
* Python 3.9+ installed
* A Google Gemini API Key from [Google AI Studio](https://aistudio.google.com/)
