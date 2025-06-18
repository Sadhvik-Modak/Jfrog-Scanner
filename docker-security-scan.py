import subprocess
import tempfile
import os
import sys
import shutil
import json
import html
from datetime import datetime

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except ImportError:
    print("Error: The 'jinja2' package is required. Install it with 'pip install jinja2'")
    sys.exit(1)

import concurrent.futures

def check_command(cmd):
    return shutil.which(cmd) is not None

def run_cmd(cmd, capture_output=True):
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=capture_output, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return None

def scan_image(image, temp_dir):
    safe_name = image.replace('/', '_').replace(':', '_')
    result_file = os.path.join(temp_dir, f"{safe_name}_scan.json")
    print(f"Scanning {image}...")
    print(f"Running JFrog scan for {image}... ", end="")
    scan_cmd = f'jf docker scan "{image}" --format simple-json'
    scan_out = run_cmd(scan_cmd)
    if scan_out is None:
        print("Error scanning. Skipping...")
        return None
    with open(result_file, "w") as rf:
        rf.write(scan_out)
    print("Done!")

    with open(result_file) as rf:
        try:
            data = json.load(rf)
        except Exception:
            data = {}
    vulns = data.get('vulnerabilities', []) or []

    # Count severities
    critical_count = sum(1 for v in vulns if v and v.get('severity') == 'Critical')
    high_count = sum(1 for v in vulns if v and v.get('severity') == 'High')
    medium_count = sum(1 for v in vulns if v and v.get('severity') == 'Medium')
    low_count = sum(1 for v in vulns if v and v.get('severity') == 'Low')
    unknown_count = sum(1 for v in vulns if v and v.get('severity') == 'Unknown')

    # Prepare vulnerability details for template
    vuln_details = []
    for idx, vuln in enumerate(vulns):
        severity = vuln.get('severity', 'Unknown')
        package = vuln.get('impactedPackageName', 'N/A')
        version = vuln.get('impactedPackageVersion', 'N/A')
        summary = vuln.get('summary', 'No summary available')
        fixed = vuln.get('fixedVersions', 'N/A')
        if fixed is None:
            fixed = 'N/A'
        # CVE handling (robust for both 'id' and 'cve' keys)
        cve_list = []
        cve_badges = []
        if 'cves' in vuln and vuln['cves']:
            for cve in vuln['cves']:
                cve_id = cve.get('cve') or cve.get('id')
                if cve_id:
                    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    cve_badges.append({'id': cve_id, 'url': url})
            cve_list = cve_badges
        truncated_summary = summary[:150] + ('...' if len(summary) > 150 else '')
        vuln_id = f'vuln_{safe_name}_{idx}'
        details = 'No detailed information available.'
        if 'jfrogResearchInformation' in vuln and vuln['jfrogResearchInformation'] and 'details' in vuln['jfrogResearchInformation']:
            details = vuln['jfrogResearchInformation']['details']
        issue_id = vuln.get('issueId', 'N/A')
        references = vuln.get('references', [])
        references_text = '\n'.join(references) if references else 'None'
        vuln_details.append({
            'severity': severity,
            'package': package,
            'version': version,
            'summary': truncated_summary,
            'fixed': fixed,
            'cves': ', '.join([badge['id'] for badge in cve_list]) if cve_list else 'N/A',
            'cve_list': cve_list,  # list of dicts with id and url
            'vuln_id': vuln_id,
            'details': details,
            'issue_id': issue_id,
            'references': references_text,
        })

    image_report = {
        'image': image,
        'safe_name': safe_name,
        'critical_count': critical_count,
        'high_count': high_count,
        'medium_count': medium_count,
        'low_count': low_count,
        'unknown_count': unknown_count,
        'vuln_details': vuln_details,
    }
    summary_row = {
        'image': image,
        'critical': critical_count,
        'high': high_count,
        'medium': medium_count,
        'low': low_count,
        'unknown': unknown_count,
        'total': critical_count + high_count + medium_count + low_count + unknown_count,
    }
    print(f"Completed scanning {image}")
    return (image_report, summary_row)

def main():
    # Check dependencies
    if not check_command('jf'):
        print("Error: JFrog CLI (jf) is not installed or not found in PATH")
        print("Please install it from https://jfrog.com/getcli/")
        sys.exit(1)
    if not check_command('docker'):
        print("Error: Docker is not installed or not found in PATH")
        sys.exit(1)

    # Create temp dir
    temp_dir = tempfile.mkdtemp()
    print(f"Temporary files will be stored in {temp_dir}")

    # Stats
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0
    total_unknown = 0

    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_report = f"docker_security_scan_report_{now}.html"

    # Get docker images
    images = run_cmd('docker images --format "{{.Repository}}:{{.Tag}}"')
    if not images:
        print("No Docker images found.")
        shutil.rmtree(temp_dir)
        sys.exit(1)
    images = [img for img in images.splitlines() if "<none>" not in img]

    image_reports = []
    summary_table = []

    # Parallel scan
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(scan_image, image, temp_dir): image for image in images}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is None:
                continue
            image_report, summary_row = result
            image_reports.append(image_report)
            summary_table.append(summary_row)
            total_critical += summary_row['critical']
            total_high += summary_row['high']
            total_medium += summary_row['medium']
            total_low += summary_row['low']
            total_unknown += summary_row['unknown']

    # Sort image_reports and summary_table for consistent navigation
    image_reports.sort(key=lambda x: x['image'])
    summary_table.sort(key=lambda x: x['image'])

    # Render HTML using Jinja2
    env = Environment(
        loader=FileSystemLoader(os.path.dirname(os.path.abspath(__file__))),
        autoescape=select_autoescape(['html', 'xml'])
    )
    template = env.get_template("docker_security_scan_report_template.html")

    rendered = template.render(
        generated_on=datetime.now(),
        report_title="Yeedu Vulnerability Report",
        image_reports=image_reports,
        summary_table=summary_table,
        total_critical=total_critical,
        total_high=total_high,
        total_medium=total_medium,
        total_low=total_low,
        total_unknown=total_unknown,
    )

    with open(html_report, "w") as f:
        f.write(rendered)

    print("Cleanup temporary files...")
    shutil.rmtree(temp_dir)
    print(f"Report generated: {html_report}")

if __name__ == "__main__":
    main()
