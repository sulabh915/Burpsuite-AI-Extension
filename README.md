# Burpsuite-AI-Extension
AIres &amp; AI Fuzzer Assistant – Burp Suite extensions powered by AI. AIres analyzes HTTP responses for sensitive data leaks, while AI Fuzzer generates and tests fuzzing payloads (SQLi, XSS, injections) on parameters, headers, and cookies. Smarter security testing with AI.

# 🤖 AIres & AI Fuzzer Assistant (Burp Suite Extensions)

[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Extension-orange)](https://portswigger.net/burp)  
[![Python](https://img.shields.io/badge/Python-Jython-blue)](https://www.jython.org/)  
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## 🔎 Overview
This repository provides **two Burp Suite extensions powered by AI**:

- **AIres.py (AI Response Analyzer):**  
  Adds an **“AI Assistant” tab** that automatically analyzes HTTP responses for sensitive information disclosure and security issues.  

- **AI Fuzzer Assistant:**  
  Uses the **Groq API** to generate fuzzing payloads for query parameters, headers, and cookies. Automatically mutates requests, sends them, and displays results in an **“AI Fuzzer” tab** with status codes and response lengths.  

Together, these tools extend Burp Suite with **AI-driven analysis and fuzzing** to speed up vulnerability discovery.

---

## ✨ Features
- 🤖 AI-assisted response analysis (detect sensitive data, leaks, misconfigs)  
- 🧪 AI-generated fuzzing payloads (SQLi, XSS, injections, header manipulation)  
- 🔑 Multiple API key rotation from `groq_keys.txt`  
- 📊 Results displayed in custom Burp tabs (`AI Assistant` & `AI Fuzzer`)  
- ⚡ Automatic request replay with response comparison  
- 📝 Debug logging for AI responses & fuzzing requests  

---

## 📦 Installation

### Requirements
- [Burp Suite](https://portswigger.net/burp) (Community or Pro)  
- [Jython 2.7.x](https://www.jython.org/)  
- [Groq API key(s)](https://console.groq.com/) for **AI Fuzzer Assistant**  

### Setup
1. Clone this repository:
   ```bash
   git clone https://github.com/yourname/ai-burp-assistants.git
   cd ai-burp-assistants
   ```
 2.Create a groq_keys.txt file in the project directory and add one or more API keys, one per line:
    ```bash
    gsk_xxxxxxxxxxxxxxxxxxxxx
    gsk_yyyyyyyyyyyyyyyyyyyyy
    ```
  3.In Burp Suite:
    Open Extender → Extensions → Add
    Set Type to Python
    Load either AIres.py or ai_fuzzer_assistant.py


    
## 🚀 Usage

### 🔎 AIres (Response Analyzer)
1. Send or intercept a request in Burp.  
2. Open the **AI Assistant** tab.  
3. The extension will show AI-generated analysis of the HTTP response.  

### 🧪 AI Fuzzer Assistant
1. Send a request with parameters (query, body, headers, cookies).  
2. Open the **AI Fuzzer** tab.  
3. The extension will:  
   - Ask AI to generate fuzzing payloads  
   - Apply mutations to the request  
   - Send requests and display results in a table  

## ⚠️ Disclaimer
These extensions are provided for educational use and authorized penetration testing only.
Do not use them against systems without explicit permission from the owner.
