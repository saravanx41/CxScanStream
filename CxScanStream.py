import aiohttp
import asyncio
import json
import pandas as pd
import urllib3
import csv
from datetime import datetime
import os
from dotenv import load_dotenv
import logging
import time
from jinja2 import Template
import urllib.parse

def setup_logging(output_dir):
    log_file = os.path.join(output_dir, 'checkmarx_report.log')
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.handlers = []
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

load_dotenv()
CHECKMARX_TOKEN = os.getenv("CHECKMARX_TOKEN")

if not CHECKMARX_TOKEN:
    raise ValueError("CHECKMARX_TOKEN environment variable not set in .env file")


class CheckmarxClient:
    def __init__(self, engines=None):
        self.base_url = "https://eu.ast.checkmarx.net/api"
        self.headers = {
            "Authorization": f"Bearer {CHECKMARX_TOKEN}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "version": "1.0"
        }
        self.scan_cache = {}
        self.engines = engines or ["sast", "sca", "kics", "apisec"]

    async def get_applications(self, session):
        url = f"{self.base_url}/applications/"
        params = {"limit": 100, "offset": 0}
        all_applications = []

        while True:
            try:
                async with session.get(url, headers=self.headers, params=params, ssl=False, timeout=30) as response:
                    response.raise_for_status()
                    data = await response.json()
                    applications = data.get('applications', [])
                    all_applications.extend(applications)
                    if len(applications) < params["limit"]:
                        break
                    params["offset"] += params["limit"]
            except aiohttp.ClientError as e:
                logger.error(
                    f"Error fetching applications: {e}, Status: {response.status if 'response' in locals() else 'N/A'}, "
                    f"Response: {await response.text() if 'response' in locals() else 'N/A'}")
                break

        logger.info(f"Fetched {len(all_applications)} applications")
        return all_applications

    async def get_last_scan(self, session, project_id, branch=None):
        url = f"{self.base_url}/projects/last-scan"
        params = {
            "project-ids": project_id,
            "engine": "sast",
            "limit": 100,
            "scan-status": "completed"
        }
        if branch:
            params["branch"] = branch
        try:
            async with session.get(url, headers=self.headers, params=params, ssl=False, timeout=30) as response:
                response.raise_for_status()
                data = await response.json()
                scan_data = data.get(project_id, {})
                if scan_data:
                    scan_data['branch'] = branch or 'any'
                return scan_data
        except aiohttp.ClientError as e:
            logger.error(f"Error fetching last scan for project {project_id}, branch {branch or 'any'}: {e}")
            return {}

    async def get_project_last_scan(self, session, project_id):
        # Try specific branches first
        for branch in ["master", "main", "develop"]:
            scan_info = await self.get_last_scan(session, project_id, branch)
            if scan_info:
                self.scan_cache[project_id] = scan_info
                logger.debug(f"Found scan for project {project_id} on branch {branch}")
                return scan_info
        # Fallback to any branch
        scan_info = await self.get_last_scan(session, project_id)
        if scan_info:
            self.scan_cache[project_id] = scan_info
            logger.debug(f"Found scan for project {project_id} on any branch")
            return scan_info
        logger.warning(f"No scan found for project {project_id} across branches or any branch")
        return {}

    async def get_sast_findings(self, session, project_id, scan_id):
        if not self._is_valid_scan_id(scan_id):
            logger.warning(f"Invalid scan ID: {scan_id} for project {project_id}")
            return {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        url = f"{self.base_url}/sast-results/"
        params = {
            "scan-id": scan_id,
            "include-nodes": "true",
            "apply-predicates": "true",
            "offset": 0,
            "limit": 1000,
            "sort": "-severity"
        }

        try:
            async with session.get(url, headers=self.headers, params=params, ssl=False, timeout=30) as response:
                response.raise_for_status()
                data = await response.json()
                severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                results = data.get('results') or []
                for result in results:
                    if result.get('state', '').upper() == 'TO_VERIFY':
                        severity = result.get('severity', '').lower()
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                return severity_counts
        except aiohttp.ClientError as e:
            logger.error(f"Error fetching SAST findings for scan {scan_id}, project {project_id}: {e}")
            return {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

    async def get_sca_findings(self, session, scan_id):
        if not self._is_valid_scan_id(scan_id):
            logger.warning(f"Invalid scan ID: {scan_id}")
            return {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        url = f"{self.base_url}/sca/graphql/graphql"
        query = {
            "query": """
            query ($isExploitablePathEnabled: Boolean!, $scanId: UUID!, $where: VulnerabilityModelFilterInput) {
                vulnerabilitiesRisksByScanId(
                    isExploitablePathEnabled: $isExploitablePathEnabled,
                    scanId: $scanId,
                    where: $where
                ) {
                    totalCount,
                    risksLevelCounts {
                        critical,
                        high,
                        medium,
                        low,
                        none,
                        empty
                    }
                }
            }
            """,
            "variables": {
                "isExploitablePathEnabled": False,
                "scanId": scan_id,
                "where": {
                    "and": [
                        {"and": [{"isDev": {"eq": False}}, {"isTest": {"eq": False}}]},
                        {"and": [{"isIgnored": {"eq": False}}]}
                    ]
                }
            }
        }

        try:
            async with session.post(url, headers=self.headers, json=query, ssl=False, timeout=30) as response:
                if response.status == 404:
                    logger.warning(f"SCA endpoint not found for scan {scan_id}, possibly not enabled")
                    return {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                response.raise_for_status()
                data = await response.json()
                risks = data.get('data', {}).get('vulnerabilitiesRisksByScanId', {}) or {}
                counts = risks.get('risksLevelCounts', {})
                return {
                    'critical': counts.get('critical', 0),
                    'high': counts.get('high', 0),
                    'medium': counts.get('medium', 0),
                    'low': counts.get('low', 0)
                }
        except aiohttp.ClientError as e:
            logger.error(
                f"Error fetching SCA findings for scan {scan_id}: {e}, Status: {response.status if 'response' in locals() else 'N/A'}, "
                f"Response: {await response.text() if 'response' in locals() else 'N/A'}")
            return {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

    async def get_kics_findings(self, session, scan_id):
        if not self._is_valid_scan_id(scan_id):
            logger.warning(f"Invalid scan ID: {scan_id}")
            return {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        url = f"{self.base_url}/kics-results"
        params = {"scan-id": scan_id, "limit": 10000, "offset": 0}

        try:
            async with session.get(url, headers=self.headers, params=params, ssl=False, timeout=30) as response:
                response.raise_for_status()
                data = await response.json()
                severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                results = data.get('results') or []
                for result in results:
                    if result.get('state', '').upper() == 'TO_VERIFY':
                        severity = result.get('severity', '').lower()
                        if severity == 'info':
                            continue
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                return severity_counts
        except aiohttp.ClientError as e:
            logger.error(f"Error fetching KICS findings for scan {scan_id}: {e}")
            return {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

    async def get_apisec_findings(self, session, scan_id):
        if not self._is_valid_scan_id(scan_id):
            logger.warning(f"Invalid scan ID: {scan_id}")
            return {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        url = f"{self.base_url}/apisec/static/api/risks/{scan_id}"
        params = {
            "page": 1,
            "per_page": 1000,
            "sorting": json.dumps([{"column": "severity", "order": "desc"}]),
            "filtering": json.dumps([{"column": "state", "operator": "in", "values": ["to_verify"]}])
        }

        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        try:
            async with session.get(url, headers=self.headers, params=params, ssl=False, timeout=30) as response:
                response.raise_for_status()
                data = await response.json()
                entries = data.get('entries') or []
                for entry in entries:
                    severity = entry.get('severity', '').lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1

                total_pages = int(data.get('total_pages', 1))
                for page in range(2, total_pages + 1):
                    params['page'] = page
                    async with session.get(url, headers=self.headers, params=params, ssl=False, timeout=30) as resp:
                        resp.raise_for_status()
                        data = await resp.json()
                        entries = data.get('entries') or []
                        for entry in entries:
                            severity = entry.get('severity', '').lower()
                            if severity in severity_counts:
                                severity_counts[severity] += 1

                return severity_counts
        except aiohttp.ClientError as e:
            logger.error(f"Error fetching APISEC findings for scan {scan_id}: {e}")
            return {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

    def _is_valid_scan_id(self, scan_id):
        if pd.isna(scan_id):
            return False
        return len(str(scan_id).strip()) > 0 and str(scan_id).lower() != 'nan'

    async def process_scan(self, session, app_name, project_id, scan_info):
        try:
            scan_id = scan_info.get('id', 'N/A')
            scan_date = scan_info.get('createdAt', 'N/A')
            branch = scan_info.get('branch', 'N/A')

            findings = {'sast': {}, 'sca': {}, 'kics': {}, 'apisec': {}}
            tasks = []
            if "sast" in self.engines:
                tasks.append(self.get_sast_findings(session, project_id, scan_id))
            if "sca" in self.engines:
                tasks.append(self.get_sca_findings(session, scan_id))
            if "kics" in self.engines:
                tasks.append(self.get_kics_findings(session, scan_id))
            if "apisec" in self.engines:
                tasks.append(self.get_apisec_findings(session, scan_id))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, engine in enumerate([e for e in ["sast", "sca", "kics", "apisec"] if e in self.engines]):
                if isinstance(results[i], Exception):
                    logger.error(
                        f"Failed to fetch {self.engines[i]} findings for scan {scan_id}, project {project_id}: {results[i]}")
                    findings[self.engines[i]] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                else:
                    findings[self.engines[i]] = results[i]

            combined_findings = {
                'critical': sum(findings[e].get('critical', 0) for e in self.engines),
                'high': sum(findings[e].get('high', 0) for e in self.engines),
                'medium': sum(findings[e].get('medium', 0) for e in self.engines),
                'low': sum(findings[e].get('low', 0) for e in self.engines)
            }

            return {
                'Repo Name': app_name,
                'Project ID': project_id,
                'Branch': branch,
                'Scan ID': scan_id,
                'Last Scan Date': scan_date,
                'SAST Critical': findings['sast'].get('critical', 0),
                'SAST High': findings['sast'].get('high', 0),
                'SAST Medium': findings['sast'].get('medium', 0),
                'SAST Low': findings['sast'].get('low', 0),
                'SCA Critical': findings['sca'].get('critical', 0),
                'SCA High': findings['sca'].get('high', 0),
                'SCA Medium': findings['sca'].get('medium', 0),
                'SCA Low': findings['sca'].get('low', 0),
                'KICS Critical': findings['kics'].get('critical', 0),
                'KICS High': findings['kics'].get('high', 0),
                'KICS Medium': findings['kics'].get('medium', 0),
                'KICS Low': findings['kics'].get('low', 0),
                'APISEC Critical': findings['apisec'].get('critical', 0),
                'APISEC High': findings['apisec'].get('high', 0),
                'APISEC Medium': findings['apisec'].get('medium', 0),
                'APISEC Low': findings['apisec'].get('low', 0),
                'Combined Critical': combined_findings['critical'],
                'Combined High': combined_findings['high'],
                'Combined Medium': combined_findings['medium'],
                'Combined Low': combined_findings['low']
            }
        except Exception as e:
            logger.error(f"Error processing scan for project {project_id}: {e}")
            return None


async def process_project(client, session, app_name, project_id, processed_project_ids):
    if project_id in processed_project_ids:
        logger.debug(f"Skipping duplicate project {project_id}")
        return None

    try:
        scan_info = client.scan_cache.get(project_id) or await client.get_project_last_scan(session, project_id)

        if not scan_info:
            logger.warning(f"No scan found for project {project_id}")
            return None

        result = await client.process_scan(session, app_name, project_id, scan_info)
        if result:
            processed_project_ids.add(project_id)
            return result
        else:
            logger.warning(f"Failed to process scan for project {project_id}: No result returned")
            return None
    except Exception as e:
        logger.error(f"Error processing project {project_id}: {e}")
        return None


def generate_html_dashboard(output_df, output_dir, current_date):
    template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Checkmarx Security Dashboard - {{ date }}</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f9; }
            .container { max-width: 1200px; margin: auto; }
            h1 { color: #2c3e50; text-align: center; }
            .summary { background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
            .summary h2 { color: #34495e; }
            .chart-container { background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; text-align: center; }
            table { width: 100%; border-collapse: collapse; background-color: #ffffff; border-radius: 8px; overflow: hidden; }
            th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
            th { background-color: #2c3e50; color: white; }
            tr:nth-child(even) { background-color: #f9f9f9; }
            tr:hover { background-color: #f1f1f1; }
            .severity-critical { color: #dc3545; font-weight: bold; }
            .severity-high { color: #fd7e14; font-weight: bold; }
            .severity-medium { color: #ffc107; font-weight: bold; }
            .severity-low { color: #28a745; font-weight: bold; }
            .pagination { margin: 20px 0; text-align: center; }
            .pagination button { margin: 0 5px; padding: 8px 16px; background-color: #2c3e50; color: white; border: none; border-radius: 4px; cursor: pointer; }
            .pagination button:disabled { background-color: #ccc; cursor: not-allowed; }
            .pagination span { margin: 0 10px; }
        </style>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head>
    <body>
        <div class="container">
            <h1>Checkmarx Security Dashboard</h1>
            <p style="text-align: center; color: #7f8c8d;">Generated on {{ date }}</p>
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Total Application:</strong> {{ total_apps }}</p>
                <p><strong>Critical Findings:</strong> <span class="severity-critical">{{ critical }}</span></p>
                <p><strong>High Findings:</strong> <span class="severity-high">{{ high }}</span></p>
                <p><strong>Medium Findings:</strong> <span class="severity-medium">{{ medium }}</span></p>
                <p><strong>Low Findings:</strong> <span class="severity-low">{{ low }}</span></p>
            </div>
            <div class="chart-container">
                <h2>Severity Distribution</h2>
                <canvas id="severityChart" width="400" height="200"></canvas>
                <script>
                    const ctx = document.getElementById('severityChart').getContext('2d');
                    new Chart(ctx, {
                        type: 'bar',
                        data: {
                            labels: ['Critical', 'High', 'Medium', 'Low'],
                            datasets: [{
                                label: 'Findings',
                                data: [{{ critical }}, {{ high }}, {{ medium }}, {{ low }}],
                                backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745'],
                                borderColor: ['#b02a37', '#e06b0d', '#e0a800', '#218838'],
                                borderWidth: 1
                            }]
                        },
                        options: {
                            scales: { y: { beginAtZero: true } },
                            plugins: { legend: { display: false } }
                        }
                    });
                </script>
            </div>
            <h2>Detailed Findings</h2>
            <div class="pagination">
                <button onclick="previousPage()">Previous</button>
                <span id="pageInfo">Page 1 of {{ total_pages }}</span>
                <button onclick="nextPage()">Next</button>
            </div>
            <table id="findingsTable">
                <tr>
                    <th>Repo</th>
                    <th>Branch</th>
                    <th>Scan Date</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Medium</th>
                    <th>Low</th>
                </tr>
                {% for row in findings %}
                <tr class="data-row">
                    <td>{{ row['Repo Name'] }}</td>
                    <td>{{ row['Branch'] }}</td>
                    <td>{{ row['Last Scan Date'][:10] }}</td>
                    <td class="severity-critical">{{ row['Combined Critical'] }}</td>
                    <td class="severity-high">{{ row['Combined High'] }}</td>
                    <td class="severity-medium">{{ row['Combined Medium'] }}</td>
                    <td class="severity-low">{{ row['Combined Low'] }}</td>
                </tr>
                {% endfor %}
            </table>
            <div class="pagination">
                <button onclick="previousPage()">Previous</button>
                <span id="pageInfoBottom">Page 1 of {{ total_pages }}</span>
                <button onclick="nextPage()">Next</button>
            </div>
            <script>
                const rows = document.querySelectorAll('.data-row');
                const rowsPerPage = 10;
                let currentPage = 1;
                const totalPages = Math.ceil(rows.length / rowsPerPage);

                function showPage(page) {
                    rows.forEach((row, index) => {
                        row.style.display = (index >= (page - 1) * rowsPerPage && index < page * rowsPerPage) ? '' : 'none';
                    });
                    document.getElementById('pageInfo').textContent = `Page ${page} of ${totalPages}`;
                    document.getElementById('pageInfoBottom').textContent = `Page ${page} of ${totalPages}`;
                    document.querySelectorAll('.pagination button')[0].disabled = page === 1;
                    document.querySelectorAll('.pagination button')[1].disabled = page === totalPages;
                    document.querySelectorAll('.pagination button')[2].disabled = page === 1;
                    document.querySelectorAll('.pagination button')[3].disabled = page === totalPages;
                }

                function previousPage() {
                    if (currentPage > 1) {
                        currentPage--;
                        showPage(currentPage);
                    }
                }

                function nextPage() {
                    if (currentPage < totalPages) {
                        currentPage++;
                        showPage(currentPage);
                    }
                }

                showPage(1);
            </script>
        </div>
    </body>
    </html>
    """

    html_path = os.path.join(output_dir, f'Checkmarx_Dashboard_{current_date.replace("-", "")}.html')
    with open(html_path, 'w') as f:
        template = Template(template)
        f.write(template.render(
            date=current_date,
            total_apps=len(set(output_df['Repo Name'])) if not output_df.empty else 0,
            critical=int(output_df['Combined Critical'].sum() if not output_df.empty else 0),
            high=int(output_df['Combined High'].sum() if not output_df.empty else 0),
            medium=int(output_df['Combined Medium'].sum() if not output_df.empty else 0),
            low=int(output_df['Combined Low'].sum() if not output_df.empty else 0),
            findings=output_df.to_dict('records') if not output_df.empty else [],
            total_pages=max(1, (len(output_df) + 9) // 10)
        ))
    return html_path


async def main():
    start_time = time.time()
    current_date = datetime.now().strftime('%Y-%m-%d')
    output_dir = f"{current_date}-Checkmarx-Weekly-Report"
    os.makedirs(output_dir, exist_ok=True)

    # Set up logging
    global logger
    logger = setup_logging(output_dir)

    client = CheckmarxClient()
    output_csv = os.path.join(output_dir, f'Final_Monthly_CX_Report_{current_date.replace("-", "")}.csv')
    output_data = []
    processed_project_ids = set()

    logger.info("Fetching applications...")
    async with aiohttp.ClientSession() as session:
        applications = await client.get_applications(session)

        if not applications:
            logger.warning("No applications found, generating empty report")
            output_df = pd.DataFrame()
            with open(output_csv, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Repo Name', 'Project ID', 'Branch', 'Scan ID', 'Last Scan Date',
                                 'SAST Critical', 'SAST High', 'SAST Medium', 'SAST Low',
                                 'SCA Critical', 'SCA High', 'SCA Medium', 'SCA Low',
                                 'KICS Critical', 'KICS High', 'KICS Medium', 'KICS Low',
                                 'APISEC Critical', 'APISEC High', 'APISEC Medium', 'APISEC Low',
                                 'Combined Critical', 'Combined High', 'Combined Medium', 'Combined Low'])
            generate_html_dashboard(output_df, output_dir, current_date)
            return

        project_tasks = []
        app_project_map = {}
        for app in applications:
            app_name = app.get('name', 'Unknown')
            project_ids = app.get('projectIds', [])
            for project_id in project_ids:
                if project_id not in processed_project_ids:
                    project_tasks.append((app_name, project_id))
                    app_project_map[project_id] = app_name

        logger.info(f"Found {len(project_tasks)} projects across {len(set(app_project_map.values()))} applications")

        batch_size = 50
        for i in range(0, len(project_tasks), batch_size):
            batch = project_tasks[i:i + batch_size]
            logger.info(f"Processing batch {i // batch_size + 1} with {len(batch)} projects")

            tasks = [process_project(client, session, app_name, project_id, processed_project_ids)
                     for app_name, project_id in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Unexpected error in batch processing: {result}")
                elif result:
                    output_data.append(result)
                else:
                    logger.debug(f"Skipped project in batch {i // batch_size + 1} due to no result")
            time.sleep(0.02)

    output_df = pd.DataFrame(output_data) if output_data else pd.DataFrame()

    column_order = [
        'Repo Name', 'Project ID', 'Branch', 'Scan ID', 'Last Scan Date',
        'SAST Critical', 'SAST High', 'SAST Medium', 'SAST Low',
        'SCA Critical', 'SCA High', 'SCA Medium', 'SCA Low',
        'KICS Critical', 'KICS High', 'KICS Medium', 'KICS Low',
        'APISEC Critical', 'APISEC High', 'APISEC Medium', 'APISEC Low',
        'Combined Critical', 'Combined High', 'Combined Medium', 'Combined Low'
    ]

    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=column_order)
        writer.writeheader()
        for row in sorted(output_data, key=lambda x: x['Repo Name']) if output_data else []:
            writer.writerow(row)

    html_path = generate_html_dashboard(output_df, output_dir, current_date)

    elapsed_time = time.time() - start_time
    logger.info(f"Processing Summary:")
    logger.info(f"Total repositories processed: {len(set(output_df['Repo Name'])) if not output_df.empty else 0}")
    logger.info(f"Total projects processed: {len(output_df)}")
    logger.info(f"Total time taken: {elapsed_time:.2f} seconds")
    logger.info(f"Critical: {int(output_df['Combined Critical'].sum() if not output_df.empty else 0)}")
    logger.info(f"High: {int(output_df['Combined High'].sum() if not output_df.empty else 0)}")
    logger.info(f"Medium: {int(output_df['Combined Medium'].sum() if not output_df.empty else 0)}")
    logger.info(f"Low: {int(output_df['Combined Low'].sum() if not output_df.empty else 0)}")
    logger.info(
        f"Reports saved: CSV: {output_csv}, HTML: {html_path}, Log: {os.path.join(output_dir, 'checkmarx_report.log')}")


if __name__ == "__main__":
    asyncio.run(main())
