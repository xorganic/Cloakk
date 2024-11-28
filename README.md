# **Cloakk**
## **Stealth AMSI Bypass and Encrypted PowerShell Executor**

## 🚀 Overview
This tool demonstrates advanced red team tradecraft for stealthy AMSI bypass and fileless PowerShell execution. Designed for penetration testers and security researchers, it leverages modern evasion techniques to bypass endpoint protections and execute encrypted payloads directly in memory.

The tool is highly modular, making it adaptable for a variety of environments, and incorporates the latest methodologies for operational security (OpSec) in 2025 and beyond.

---

## 🔥 Features
- **Dynamic AMSI Bypass**:  
  Patches both `AmsiScanBuffer` and `AmsiInitialize` functions dynamically at runtime.  
- **Indirect Syscall Execution**:  
  Implements syscall stomping via a custom trampoline for `NtProtectVirtualMemory`.  
- **Encrypted Payload Execution**:  
  Decrypts and executes PowerShell commands directly in memory for fileless operation.  
- **Polymorphic Obfuscation**:  
  Protects hardcoded strings and API names to evade static analysis.  
- **Sandbox Detection**:  
  Avoids execution in virtualized or monitored environments.  
- **Runtime API Resolution**:  
  No reliance on hardcoded module names or function addresses.  

---

## 🛠️ Prerequisites
- **Supported OS**: Windows 10/11 or later.
- **Tools**: Visual Studio (or equivalent C/C++ compiler), admin privileges for execution.
- **Dependencies**:
  - `mscoree.lib` for CLR integration.
  - Windows SDK for syscall functionality.

---

## 💻 Usage

### **Clone the Repository**:
```bash
git clone https://github.com/xorganic/Cloakk.git
cd stealth-amsi-bypass
```

### Compile the Code:
Open the project in Visual Studio and build in Release mode.
On linux: 
```bash
x86_64-w64-mingw32-gcc -o Cloakk.exe Cloakk.c -lmscoree -lkernel32 -luser32 -ladvapi32
```
Execute the Binary:
```bash
Cloakk.exe
```
### Customize the Payload:
Replace the encryptedCommand with your XOR-encrypted PowerShell script:

```c
const char* encryptedCommand = "\x15\x13\x12..."; // Encrypted payload
executeEncryptedPowerShell(encryptedCommand, 42); // Key for decryption
```
## ⚠️ Legal Disclaimer
This tool is intended for educational purposes only. Use it solely in authorized penetration testing environments with explicit consent from stakeholders. Misuse of this tool can lead to severe legal consequences.

## 📖 How It Works
1. AMSI Patch
Dynamically resolves AMSI-related APIs.
Utilizes indirect syscalls to modify memory protections.
Applies polymorphic patches (xor eax, eax; ret) to disable AMSI scanning.
2. Encrypted PowerShell Execution
The payload is XOR-encrypted for stealth.
Decrypted at runtime and executed in a .NET CLR runspace.
3. Sandbox Avoidance
Detects common artifacts like VBoxGuest.dll or SbieDll.dll.
Exits gracefully when a virtualized or debugged environment is detected.
## 🔍 Use Cases
Red Team Operations:
Execute payloads while bypassing modern EDR/AV solutions.
Security Research:
Understand advanced techniques for AMSI evasion and PowerShell obfuscation.
Blue Team Training:
Develop detection rules and improve endpoint monitoring strategies.
## 📈 Why Share This?
This tool highlights the importance of staying ahead in cybersecurity. As defenders strengthen their systems, offensive techniques evolve. Sharing knowledge fosters growth and prepares both red and blue teams for the challenges of 2025 and beyond.

## 🤝 Contribute
Found an issue? Have suggestions? Feel free to open a pull request or contact me!
