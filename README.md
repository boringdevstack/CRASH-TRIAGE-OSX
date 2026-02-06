# 🧪 Crash Triage (macOS / LLDB)

A lightweight **crash-triage automation tool for macOS** built on top of the LLDB Python API.  
This tool launches a target binary, monitors execution, detects crash conditions, and produces **useful debugging and vulnerability-research context automatically**.

It is designed for **security researchers, fuzzing workflows, and vulnerability analysis pipelines**.

---

## 🔍 Overview

CrashTriageOSX automates several repetitive debugging tasks after a crash:

- Launching binaries through LLDB
- Capturing stop events
- Selecting the faulting thread
- Generating stack traces
- Disassembling instructions near the crash
- Running heuristic crash analysis
- Logging triage output

## ⚙️ Features

- LLDB Python API integration
- Crash event monitoring
- Automatic faulting thread selection
- Stack trace collection
- Instruction disassembly near PC
- Heuristic crash analysis indicators
- Environment variable preservation during launch
- Scriptable triage workflow

---

## 🧠 Analysis Indicators

The tool uses an analyzer module to detect common vulnerability patterns:

- Access violation near NULL
- Access violation near stack pointer
- Suspicious stack functions
- Illegal instruction detection
- Program counter anomalies
- Large stack usage
- Crash stop descriptions

These indicators help quickly determine **exploitability and crash classification**.

---

## 📦 Requirements

- macOS
- Python 3
- LLDB with Python bindings
- Xcode Command Line Tools or full Xcode install

Install LLDB tools if needed:

```bash
xcode-select --install
