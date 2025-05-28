## CxScanStream - Prioritize your production vulnerabilities from checkmarx scan.

CxScanStream is a lightweight Python script that generates detailed security reports from Checkmarx One scans, solving key limitations in Checkmarx’s native reporting. Checkmarx One requires manual configuration to filter dev/test dependencies per repository and lacks a built-in option to export all repository findings in a detailed CSV. CxScanStream automates this, prioritizing production vulnerabilities and providing CSV and HTML reports for SAST, SCA, KICS, and APISEC scans.

### Why CxScanStream?
- **Production Focus**: Prioritizes production issues for faster remediation.
- **Solves Manual Effort**: Automatically filters dev/test dependencies, eliminating manual checkmarx scan configuration for SCA findings.
- **Detailed Reporting**: Exports comprehensive CSV and CISO-friendly HTML reports.
- **Scalable**: Handles upto 10,000+ repositories efficiently.

### Features
- **Production-First**: Ignores dev/test dependencies in SCA scans.
- **CSV Report**: Creates Final_Monthly_CX_Report_YYYYMMDD.csv with findings (Repo Name, Project ID, Branch, Scan ID, severities for SAST/SCA/KICS/APISEC).
- **HTML Dashboard**: Generates Checkmarx_Dashboard_YYYYMMDD.html with pagination for 10,000+ repos, severity chart, and summary.
- **All Scans**: Processes all SAST, SCA, KICS, APISEC scans on master, main, develop branches.(or update script for custom branches)
- **Fast**: ~50-60 seconds for 140 projects.
- **Simple Auth**: Uses CHECKMARX_TOKEN from .env. 

### Requirements
- Python: 3.8+
- Dependencies:pip install aiohttp pandas urllib3 python-dotenv jinja2

## Checkmarx One Setup

### Scans:

- Enable SAST, SCA, KICS, or APISEC scans for projects.
- Ensure scans are “completed.”
- Region: Script uses eu.ast.checkmarx.net. For other regions (e.g., US), edit: self.base_url = "https://us.ast.checkmarx.net/api"

### Installation & Usage
```
* Clone the Repository:

git clone https://github.com/your_username/cxscanstream.git
cd cxscanstream

* Set Up Virtual Environment:
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate


* Install Dependencies:
pip install aiohttp pandas urllib3 python-dotenv jinja2

* Usage:

python checkmarx_report.py

* Check Outputs:

Folder: YYYY-MM-DD-Checkmarx-Weekly-Report (e.g., 2025-06-02-Checkmarx-Weekly-Report)
CSV: Final_Monthly_CX_Report_YYYYMMDD.csv
HTML: Checkmarx_Dashboard_YYYYMMDD.html
```

#### Troubleshooting:

- 401 Unauthorized:

  Verify CHECKMARX_TOKEN in .env.
  If expired, generate a new token in Checkmarx One.

#### How to get checkmarx token:
```
- Log into Checkmarx One in your browser.

- Right-click, select Inspect, go to Network tab.

- Interact with the interface (e.g., view Projects) to trigger API calls.

- Find an API request (e.g., /api/applications/), check Headers, copy the Authorization token.

- Save in .env:
  echo "CHECKMARX_TOKEN=your_token" > .env
```

- Ensure SCA is enabled or exclude it:self.engines = ["sast", "kics", "apisec"]

#### Missing Projects:

- Confirm projects have scans. Check logs for “No scan found.”

#### Contributing
Contributions are welcome! Submit issues or pull requests on GitHub. Ensure application names match repo names in Checkmarx One for compatibility.

#### License:
MIT License. See LICENSE for details.

#### Contact:
For support, open a GitHub issue or connect on LinkedIn: [[LinkedIn Profile](https://www.linkedin.com/in/06saravana/)]. Share logs (checkmarx_report.log) for debugging.

