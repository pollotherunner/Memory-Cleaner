# Memory-Cleaner
Memory Cleaner is a C++ utility for cleaning specific strings from the memory of running processes. It utilizes Windows API functions to scan and overwrite memory regions within target processes. This can be particularly useful for security or privacy purposes, ensuring sensitive data is removed from process memory.

# Usage Example

- Clear from process name
```cpp
g_mem_cleaner.clear_string_by_procname(L"target_process", L"skript.gg");
```

- Clear from process PID
```cpp
g_mem_cleaner.clear_string_by_pid(/*pid*/666, L"skript.gg");
```
