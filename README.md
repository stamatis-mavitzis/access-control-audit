# Access Control Logging System
**Authors:**
- Stamatios Mavitzis (AM: 2018030040)
- Christos Christou (AM: 2018030126)

---

## Overview
This project implements an **Access Control Audit System** in C that monitors and logs file access operations across the system. It is divided into three main components:

1. **Audit Logging Library (`audit_logger.so`)** – A shared library that intercepts file operations (`fopen`, `fwrite`, `fclose`) using the **LD_PRELOAD** mechanism and logs detailed information about each event.  
2. **Audit Log Analyzer (`audit_monitor`)** – A command-line tool that analyzes the generated logs and detects suspicious activity or provides statistics for specific files.  
3. **Test Program (`test_audit`)** – A program that performs various file operations to test and demonstrate the auditing system.  

---

## 1. Audit Logging Library (`audit_logger.c`)

### Purpose
The audit logger overrides standard file I/O functions from the C library and logs all access events to a system-wide log file.  

### How it Works
- Each time a process calls `fopen()`, `fwrite()`, or `fclose()`, our custom versions are executed instead.  
- The library uses **`dlsym()`** to call the original functions after performing logging actions.  
- Before logging, it collects:  
  - **User ID (UID)** using `getuid()`  
  - **Process ID (PID)** using `getpid()`  
  - **Filename** (absolute path)  
  - **Date & Time** in UTC format  
  - **Operation Type:**  
    - `0` → file created  
    - `1` → file opened  
    - `2` → file written  
    - `3` → file closed  
  - **Denied flag:** 1 if access is denied, 0 otherwise  
  - **SHA-256 Hash:** computed using OpenSSL for file integrity checking  

### Log File
All log entries are written in append mode to:  
```
/tmp/access_audit.log
```
Each line represents one event in a structured, space-separated format.

### Example Log Entry
```
UID=1000 PID=2345 File=/home/user/data.txt Date=2025-11-11 Time=13:20:04 Op=2 Denied=0 Hash=d2f3a8...
```

---

## 2. Audit Log Analyzer (`audit_monitor.c`)

### Purpose
The analyzer reads and interprets the `access_audit.log` file to detect security incidents or report user activity.  

### Available Commands

#### 1. Detect Suspicious Users
```
./audit_monitor -s
```
- Parses the log file and lists all **user IDs (UIDs)** that attempted to access **more than 5 distinct files** where the operation was **denied**.  
- Useful for identifying potential intrusions or misconfigured access permissions.

#### 2. Analyze File Activity
```
./audit_monitor -i <filename>
```
- For a specific file, prints all users who accessed it.  
- Counts how many times each user **modified** the file (based on write operations or changed hashes).  
- Displays how many **unique modifications** occurred in total.  

### Example Output
```
File: /home/user/report.txt
Accessed by users: 1000, 1001

User 1000: 3 modifications
User 1001: 1 modification
Total unique modifications: 3
```

---

## 3. Test Program (`test_audit.c`)

### Purpose
This program generates various file operations to produce real audit logs for testing.  

### Operations Performed
- Creates several test files.  
- Writes and modifies data multiple times.  
- Attempts to open files without permissions to trigger denied events.  

### Usage
Run the test program with the audit logger preloaded:  
```bash
LD_PRELOAD=./audit_logger.so ./test_audit
```
This command will generate a log file in `/tmp/access_audit.log`.

---

## 4. Compilation Instructions

### Using the Makefile
The provided **Makefile** automatically compiles all components.  
To build everything, run:  
```bash
make
```

This will produce:  
- `audit_logger.so` (shared library)  
- `audit_monitor` (analyzer tool)  
- `test_audit` (testing program)

To clean up build artifacts:  
```bash
make clean
```

### Running Analysis Targets via Makefile

The Makefile also includes convenience targets to run monitoring commands directly.

#### Detect Suspicious Users
You can use:
```bash
make monitor-s
```
This executes:
```bash
./audit_monitor -s
```
It scans `/tmp/access_audit.log` and lists all users (UIDs) who attempted to access **more than 5 distinct files** where access was **denied**.

#### Analyze a Specific File
You can use:
```bash
make monitor-file FILE=<path_to_file>
```
For example:
```bash
make monitor-file FILE=example1.txt
```
This executes:
```bash
./audit_monitor -i example1.txt
```
and displays per-user modification counts and the total number of unique modifications.

---

## 5. Example Workflow

1. **Build all binaries:**  
   ```bash
   make
   ```
2. **Run the test program with auditing enabled:**  
   ```bash
   LD_PRELOAD=./audit_logger.so ./test_audit
   ```
3. **View the generated log file:**  
   ```bash
   cat /tmp/access_audit.log
   ```
4. **Detect suspicious users:**  
   ```bash
   ./audit_monitor -s
   ```
5. **Inspect a specific file’s activity:**  
   ```bash
   ./audit_monitor -i example1.txt
   ```

---

## 6. Implementation Details

- **Language:** C  
- **Platform:** Ubuntu 24.04 LTS  
- **Libraries Used:**  
  - `dlfcn.h` for dynamic linking (LD_PRELOAD mechanism)  
  - `openssl/evp.h` for SHA-256 hashing  
  - `sys/stat.h`, `time.h`, `unistd.h` for system info and timestamps  

### Key Features
- Transparent file operation interception  
- Detailed logging of all activity  
- SHA-256 integrity tracking  
- Command-line analytics for administrators  

---

## 7. Notes
- The system must be executed with user permissions that allow writing to `/tmp/access_audit.log`.  
- Make sure OpenSSL development libraries are installed before compiling:  
  ```bash
  sudo apt install libssl-dev
  ```
- The audit log file grows over time; consider cleaning it periodically.  
- Invalid command-line arguments to `audit_monitor` trigger a help message.  

---

## 8. File List

| File | Description |
|------|--------------|
| `audit_logger.c` | Implements LD_PRELOAD-based interception and logging |
| `audit_monitor.c` | Parses and analyzes the generated log file |
| `test_audit.c` | Demonstrates file access operations |
| `Makefile` | Automates compilation and linking |
| `README.md` | Documentation of the system |

---

## 9. Example Repository Structure
```
2018030040_2018030126_assign3/
│
├── audit_logger.c
├── audit_monitor.c
├── test_audit.c
├── Makefile
├── README.md
└── access_audit.log (generated during runtime)
```