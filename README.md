PII-Sentinel -- Flixkart
=======================

An intelligent system for detecting and anonymizing Personally Identifiable Information (PII) in e-commerce platforms

**Author:** Pagilla Siddhartha Reddy

* * * * *

 Introduction
---------------

PII-Sentinel is a privacy-first solution designed for modern e-commerce applications.\
It safeguards customer data by identifying and obfuscating sensitive information in real time, reducing the risk of leaks while preserving the analytical value of logs and datasets.

By leveraging carefully crafted regex rules and smart redaction strategies, the system provides effective defense against unintentional data exposure.

* * * * *

Features
---------

1.  **Automated PII Detection**

    -   Identifies sensitive fields such as phone numbers, Aadhaar, passport numbers, UPI IDs, emails, names, addresses, and IP addresses using regex-based patterns.

2.  **Adaptive Masking Strategies**

    -   Applies context-specific redaction (e.g., partially masking numbers, anonymizing names, preserving email domains) while keeping data meaningful for analysis.

3.  **Risk-Aware Analysis**

    -   Detects and flags records with multiple PII elements present together, indicating higher privacy risks, and applies stricter redaction.

4.  **CSV-to-CSV Workflow**

    -   Processes raw CSV input and generates a new CSV output with redacted JSON and a PII flag for easy integration into data pipelines.

##  Supported PII Types

| **Category** | **Pattern Detected** | **Redaction Example** |
| --- | --- | --- |
| Email | Standard email format | `john@example.com → jXXXn@example.com` |
| Passport | One letter + 7 digits | `A1234567 → AXXXXX67` |
| IP Address | IPv4 style numbers | `192.168.0.55 → 192.168.0.XXX` |
| Aadhaar | 12 consecutive digits | `123456789012 → 1234XXXX9012` |
| Name | Multi-part personal names | `Jane Smith → JXXe SXXXh` |
| UPI ID | Identifier in `user@bank` form | `user@upi → userXXX@upi` |
| Address | Text containing PIN codes | `[REDACTED_ADDRESS]` |
| Phone Number | 10-digit mobile sequence | `9876543210 → 98XXXXXX10` |

---

Installation
---------------

### 1\. Clone the Repository

```
git clone https://github.com/siddhartha64/PII-Sentinel.git
cd PII-Sentinel

```



### 2\. Requirements

-   Python **3.6+**

-   Uses only standard libraries: `csv`, `json`, `re`, `sys`

No additional installation is required.

* * * * *

Quick Start
--------------

### 1\. Run the Detector

`python detector_Pagilla_Siddhartha_Reddy.py iscp_pii_dataset.csv`

### 2\. Input Format

CSV file should look like:

`record_id,data_json
1,"{""name"": ""John Doe"", ""phone"": ""1234567890"", ""email"": ""john@example.com""}"
2,"{""first_name"": ""Jane"", ""last_name"": ""Smith"", ""aadhar"": ""123456789012""}"`

### 3\. Output

The script generates `redacted_output_Pagilla_Siddhartha_Reddy.csv` with the following columns:

-   **record_id** → Original ID

-   **redacted_data_json** → Masked JSON

-   **is_pii** → Boolean flag
  * * * * *
 Architecture
---------------

-   **Standalone Detection** → Directly masks sensitive fields
-   **Combinatorial Detection** → Flags risky identity leaks when multiple PII types appear together

### Flow:

```
Input data → Detector
PII detected → Masked inline
Logs/cleaned data → Output file or downstream system
```

 Project Structure
--------------------
```
PII-Sentinel/
├── detector_Pagilla_Siddhartha_Reddy.py          # Main detection script
├── iscp_pii_dataset.csv                          # Sample dataset
├── redacted_output_Pagilla_Siddhartha_Reddy.csv  # Masked output
├── README.md                                     # Project documentation
```
