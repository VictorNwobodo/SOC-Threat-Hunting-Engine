# Production SOC Threat Hunting Engine

A production-style Security Operations Center (SOC) threat hunting pipeline built with **Python** and **DuckDB** to process, normalize, reconcile, and analyze **750,000 security events** across multiple telemetry sources.

This project was completed as part of my cybersecurity internship, where the objective was not just to process logs, but to build a complete workflow that ensures data integrity, reduces false positives, and uncovers attack activity across different log sources.

Whether you're reviewing this project for the internship or you've simply come across this repository, this documentation will walk you through everything you need to understand and run the project.

# Author

**Nwobodo Chukwuemeka Victor**

---

# Table of Contents

- [Project Overview](#project-overview)
- [How the Pipeline Works](#how-the-pipeline-works)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running the Project](#running-the-project)
- [Project Outputs](#project-outputs)
- [Data Quality Results](#data-quality-results)
- [Challenges I Faced](#challenges-i-faced)
- [Lessons Learned](#lessons-learned)
- [Future Improvements](#future-improvements)

---

# Project Overview

When I started this project, I thought threat hunting was mostly about writing detection rules.

As I worked through the project, I realized something much more important.

Before you can detect attacks, you first need data you can trust.

Security logs usually come from different systems, different vendors, and different formats. Some records are incomplete, some contain invalid data, and others use different field names for the same information.

If those problems aren't handled properly, detection becomes unreliable.

The purpose of this project is to solve that problem by building a workflow that:

- Reads raw security logs from multiple telemetry sources
- Normalizes different log formats into one consistent structure
- Preserves invalid records by sending them to quarantine instead of deleting them
- Stores normalized events inside DuckDB
- Compares suspicious activity against approved maintenance records
- Detects attack patterns across multiple log sources
- Produces investigation-ready outputs

By the end of the workflow, every log is accounted for, suspicious activities are classified more accurately, and analysts have cleaner data to investigate.

---

# How the Pipeline Works

The project follows a simple workflow.

```text
Raw Security Logs
        │
        ▼
Normalization & Validation
        │
        ▼
DuckDB Database
        │
        ▼
Discrepancy Reconciliation
        │
        ▼
Threat Hunting Queries
        │
        ▼
Campaign Graph & Investigation Outputs
```

Each stage prepares the data for the next one until the final hunting results are generated.

---

# Project Structure

```
project/
│
├── hunt_engine/
│   Main Python application
│
├── queries/
│   SQL threat hunting queries
│
├── raw/
│   Original evidence and discrepancy files
│
├── tests/
│   Unit tests
│
├── work/
│   Generated outputs
│
├── requirements.txt
│
└── README.md
```

### Folder Explanation

### `hunt_engine/`

Contains the Python code responsible for:

- Reading raw log files
- Normalizing different schemas
- Loading events into DuckDB
- Running reconciliation
- Executing threat hunting queries

---

### `queries/`

Contains SQL files used for threat hunting.

These queries correlate events across multiple log sources to detect attack campaigns.

---

### `raw/`

Contains the original datasets provided for the project.

These files are never modified directly.

---

### `tests/`

Contains unit tests used to verify that normalization works correctly before processing the complete dataset.

---

### `work/`

Stores every generated output after the pipeline runs.

Examples include:

- normalized datasets
- campaign graph
- reports
- reconciliation results

---

# Prerequisites

Before running the project, make sure you have:

- Python 3.10 or newer
- Git
- Virtual Environment (recommended)

---

# Installation

## 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
```

```bash
cd YOUR_REPOSITORY
```

---

## 2. Create a virtual environment

```bash
python -m venv .venv
```

---

## 3. Activate the virtual environment

### Windows

```powershell
.\.venv\Scripts\Activate.ps1
```

### Linux / macOS

```bash
source .venv/bin/activate
```

---

## 4. Install dependencies

```bash
pip install -r requirements.txt
```

---

# Running the Project

The project is designed to be executed in four simple stages.

---

## Step 1 — Run Unit Tests

Before processing the complete dataset, I first verified that the normalization rules were working correctly.

```powershell
pytest -q tests
```

### What this does

- Verifies timestamp extraction
- Tests schema normalization
- Ensures malformed records are handled correctly


---

## Step 2 — Build the Dataset

Next, the raw evidence files are processed and loaded into DuckDB.

```powershell
python -m hunt_engine.cli build-input .\raw\evidence .\work
```

### What this does

- Reads every raw log
- Normalizes different schemas
- Sends invalid records to quarantine
- Loads clean events into DuckDB

One interesting lesson I learned here was the importance of batching.

Initially, I inserted records one at a time, which worked but was very slow.

After changing the ingestion process to batch thousands of records together before writing them to DuckDB, the execution time improved dramatically.


---

## Step 3 — Reconcile Approved Changes

Once all events have been loaded, the engine compares suspicious activities with approved maintenance records.

```powershell
python -m hunt_engine.cli reconcile .\raw\private\discrepancy.json .\work
```

### What this does

This stage helps reduce false positives.

Instead of treating every alert as an attack, the engine checks whether the activity:

- was approved
- occurred within the maintenance window
- was performed by an authorized user
- matches the correct corporate asset

Activities that satisfy all these checks are classified as legitimate maintenance.

Anything else remains available for investigation.


---

## Step 4 — Run Threat Hunting Queries

The final stage searches for attack patterns across multiple log sources.

```powershell
python -m hunt_engine.cli hunt .\work .\queries
```

### What this does

The SQL queries correlate events across:

- Authentication logs
- DNS logs
- Firewall logs
- Endpoint telemetry
- Web gateway logs

Instead of looking at one log source in isolation, the engine connects related events together to uncover larger attack campaigns.

The results are exported for further investigation.


---

# Project Outputs

After the pipeline finishes successfully, several output files are generated inside the **work/** directory.

Examples include:

- Normalized event data
- Quarantine records
- Data quality register
- Reconciliation results
- Campaign graph
- Investigation outputs

These files become the starting point for further threat analysis.

---

# Data Quality Results

One requirement of this project was making sure every log was accounted for.

Instead of silently discarding bad records, invalid entries were quarantined while clean events continued through the pipeline.

| Log Source | Accepted | Quarantined | Total |
|------------|---------:|------------:|------:|
| Authentication | 150,014 | 5 | 150,019 |
| Web Gateway | 149,878 | 5 | 149,883 |
| DNS | 149,906 | 5 | 149,911 |
| Firewall | 150,041 | 5 | 150,046 |
| Endpoint | 150,136 | 5 | 150,141 |
| **Total** | **749,975** | **25** | **750,000** |

This approach ensured that no security event disappeared without explanation.

---

# Challenges I Faced

This project wasn't just about writing code.

It required understanding how different parts of a security pipeline work together.

Some of the challenges I encountered included:

- Handling different log schemas
- Preserving malformed records instead of deleting them
- Improving database performance during ingestion
- Understanding how reconciliation reduces false positives
- Writing SQL queries that correlate multiple telemetry sources efficiently

Each challenge taught me something new about building scalable security workflows.

---

# Lessons Learned

This project completely changed how I think about threat hunting.

I started by focusing on detections, but I finished by appreciating the importance of data quality.

I learned that even the best detection rules become unreliable if the underlying data isn't trustworthy.

I also saw how small implementation decisions, like batch processing or filtering data before joining large datasets, can have a significant impact on performance.

Most importantly, I learned that successful security operations depend on building reliable systems that analysts can trust.

---

# Future Improvements

If I continue developing this project, I'd like to add:

- Docker support
- Automated CI/CD testing with GitHub Actions
- Interactive dashboards
- Additional threat hunting queries
- MITRE ATT&CK technique mapping
- Automated reporting
- Visualization of campaign relationships

If this project helps you understand SOC workflows or threat hunting better, feel free to fork the repository, explore the code, and build on it.
