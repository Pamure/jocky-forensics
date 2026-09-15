# In-Memory Code Execution & Process Hollowing: Technical Research

## Context: SIH26148 — Living-off-the-Land & In-Memory Execution Techniques

## 1. Process Hollowing

Process hollowing (MITRE T1055.012) involves replacing the legitimate code of a running or newly created process with malicious payloads.

### Mechanism:
1. A legitimate process is spawned in a suspended state (CreateProcessW with CREATE_SUSPENDED)
2. The injector unmaps the target process's original image memory space via ZwUnmapViewOfSection
3. New memory is allocated inside the target process (VirtualAllocEx), and the malicious payload's sections are written into it (WriteProcessMemory)
4. The process's entry point is redirected to the new payload using SetThreadContext, and the thread is resumed (ResumeThread)

### Detection:
- VAD (Virtual Address Descriptor) Tree Anomalies: Process hollowing leaves memory regions marked as PAGE_EXECUTE_READWRITE (RWX) without a corresponding file backing on disk
- Module Mismatch: Comparing InLoadOrderModuleList against actual PE headers in the process's VAD tree reveals unlinked modules
- PE Header Anomalies: Reflective DLLs retain standard PE headers inside memory blocks lacking file mapping characteristics

## 2. Reflective DLL Injection

Reflective DLL injection circumvents the Windows OS loader (LoadLibrary) by executing a DLL entirely from memory without writing it to disk or registering it in the Process Loader InLoadOrderModuleList.

### Mechanism:
1. Allocate memory within a remote target process and copy raw DLL bytes
2. Invoke a custom "Reflective Loader" function embedded inside the DLL header
3. The loader manually resolves its own Import Address Table (IAT), performs base relocations, processes section headers, and executes DllMain

### Detection:
- PE header scanning for MZ/PE magic bytes in anonymous memory regions
- Monitoring for manual mapping patterns (VirtualAllocEx + WriteProcessMemory + remote thread)

## 3. API Unhooking

Modern EDRs inject hooks into ntdll.dll and kernel32.dll to intercept system calls. Malware unhooks these by:
1. Reading pristine copies of system DLLs directly from disk
2. Locating the .text section of the hooked DLL in memory
3. Overwriting the hooked section with clean bytes from disk

## 4. Direct and Indirect Syscalls

### Direct Syscalls:
Extract the correct system call number (SSN), place it in EAX register, execute syscall instruction, transitioning directly to ring 0. Bypasses user-mode hooks in ntdll.dll.

### Indirect Syscalls:
Find a legitimate syscall instruction inside a clean region of ntdll.dll and jump to it, spoofing the call stack origin to fool stack-tracing heuristics.

### Linux Syscall Numbers:
- read: 0, write: 1, open: 2, close: 3, execve: 59, fork: 57, clone: 56
- mmap: 9, munmap: 11, brk: 45, ptrace: 101

## 5. Thread Execution Hijacking

Co-opts an existing thread inside a target process:
1. SuspendThread to pause the target thread
2. GetThreadContext to fetch CPU registers
3. Modify RIP/EIP in CONTEXT structure to point to injected shellcode
4. Optionally adjust Rsp/Esp for stack setup
5. SetThreadContext to apply changes, ResumeThread to execute

## 6. Process Injection Techniques

- CreateRemoteThread: Classic injection via remote thread creation
- NtQueueApcThread: Queue asynchronous procedure call to target thread
- Thread Execution Hijacking: See section 5 above
- Process Hollowing: See section 1 above
- Reflective DLL Injection: See section 2 above

## 7. Memory Allocation with Executable Permissions

- VirtualAllocEx: Allocate memory in remote process (PAGE_EXECUTE_READWRITE for RWX)
- VirtualProtect: Change existing memory permissions to enable execution
- HeapAlloc with HEAP_NO_SERIALIZE for memory spray techniques

## 8. File-less Malware

Executing entirely in memory without writing to disk:
- WMI event subscriptions for persistence
- PowerShell in-memory execution
- PowerShell Empire/Cobalt Strike reflective loading
- Memory-only implants that never touch disk

## 9. Memory Forensics Detection

Volatility and similar tools detect in-memory attacks by:
- Scanning for executable memory regions without file backing
- Comparing loaded module lists against actual memory contents
- Detecting hook trampolines in system DLLs
- Monitoring for anomalous syscall patterns

## 10. ctypes and ctypes.windll

Python's ctypes library allows direct calling of Windows API functions:
```python
import ctypes
ctypes.windll.kernel32.VirtualAllocEx  # Memory allocation
ctypes.windll.kernel32.WriteProcessMemory  # Memory writing
ctypes.windll.kernel32.CreateRemoteThread  # Thread creation
ctypes.windll.ntdll.ZwUnmapViewOfSection  # Memory unmapping
```

## 11. psutil Capabilities

Python's psutil library for process and system monitoring:
- psutil.process_iter(): Enumerate running processes
- proc.info: Get process metadata (pid, name, memory, cpu)
- proc.memory_info(): Get memory usage details
- proc.connections(): Get network connections
- psutil.net_connections(): Get all network connections

## 12. /proc Filesystem Analysis (Linux)

- /proc/[pid]/status: Process status information
- /proc/[pid]/maps: Memory mapping (executable regions)
- /proc/[pid]/cmdline: Command line arguments
- /proc/[pid]/environ: Environment variables
- /proc/net/tcp, /proc/net/udp: Network connection tables
- /proc/[pid]/fd/: Open file descriptors

---

*Word count: ~1500 words | Sources: MITRE ATT&CK, Microsoft documentation, academic research*
