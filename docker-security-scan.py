import subprocess
import tempfile
import os
import sys
import shutil
import json
import html
from datetime import datetime
import argparse

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except ImportError:
    print("Error: The 'jinja2' package is required. Install it with 'pip install jinja2'")
    sys.exit(1)

import concurrent.futures
import logging

# --- Enhanced Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("yeedu-jfrog-scan")

def check_command(cmd):
    found = shutil.which(cmd) is not None
    if found:
        logger.debug(f"Command '{cmd}' found in PATH.")
    else:
        logger.error(f"Command '{cmd}' not found in PATH.")
    return found

def run_cmd(cmd, capture_output=True):
    logger.debug(f"Running command: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=capture_output, text=True)
        logger.debug(f"Command succeeded: {cmd}")
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {cmd}\nReturn code: {e.returncode}\nOutput: {e.output}\nError: {e.stderr}")
        return None

def scan_image(image, temp_dir):
    safe_name = image.replace('/', '_').replace(':', '_')
    result_file = os.path.join(temp_dir, f"{safe_name}_scan.json")
    logger.info(f"Scanning image: {image}")
    logger.debug(f"Result file: {result_file}")
    scan_cmd = f'jf docker scan "{image}" --format simple-json'
    logger.info(f"Running JFrog scan for {image}...")
    scan_out = run_cmd(scan_cmd)
    if scan_out is None:
        logger.error(f"Error scanning image '{image}'. Skipping.")
        return None
    with open(result_file, "w") as rf:
        rf.write(scan_out)
    logger.info(f"Scan completed for {image}")

    with open(result_file) as rf:
        try:
            data = json.load(rf)
        except Exception as ex:
            logger.error(f"Failed to parse JSON for image '{image}': {ex}")
            data = {}
    vulns = data.get('vulnerabilities', []) or []

    # Count severities
    critical_count = sum(1 for v in vulns if v and v.get('severity') == 'Critical')
    high_count = sum(1 for v in vulns if v and v.get('severity') == 'High')
    medium_count = sum(1 for v in vulns if v and v.get('severity') == 'Medium')
    low_count = sum(1 for v in vulns if v and v.get('severity') == 'Low')
    unknown_count = sum(1 for v in vulns if v and v.get('severity') == 'Unknown')

    logger.info(f"Image '{image}': Critical={critical_count}, High={high_count}, Medium={medium_count}, Low={low_count}, Unknown={unknown_count}")

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
            'cve_list': cve_list,
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
    logger.debug(f"Completed processing image '{image}'")
    return (image_report, summary_row)

def main():
    logger.info("Starting Yeedu JFrog Docker Vulnerability Scan")

    # --- Argument parsing for --images ---
    parser = argparse.ArgumentParser(description="Scan Docker images for vulnerabilities using JFrog Xray.")
    parser.add_argument(
        "--images",
        nargs="+",
        help="List of Docker images to scan (e.g. repo1:tag1 repo2:tag2). If not provided, all local images will be scanned."
    )
    args = parser.parse_args()

    # Check dependencies
    if not check_command('jf'):
        logger.critical("JFrog CLI (jf) is not installed or not found in PATH. Exiting.")
        print("Error: JFrog CLI (jf) is not installed or not found in PATH")
        print("Please install it from https://jfrog.com/getcli/")
        sys.exit(1)
    if not check_command('docker'):
        logger.critical("Docker is not installed or not found in PATH. Exiting.")
        print("Error: Docker is not installed or not found in PATH")
        sys.exit(1)

    # Create temp dir
    temp_dir = tempfile.mkdtemp()
    logger.info(f"Temporary files will be stored in {temp_dir}")

    # Stats
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0
    total_unknown = 0

    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_report = f"docker_security_scan_report_{now}.html"

    # Get docker images
    if args.images:
        images = args.images
        logger.info(f"Scanning only provided images: {images}")
    else:
        logger.info("Retrieving Docker images...")
        images_str = run_cmd('docker images --format "{{.Repository}}:{{.Tag}}"')
        if not images_str:
            logger.warning("No Docker images found. Exiting.")
            print("No Docker images found.")
            shutil.rmtree(temp_dir)
            sys.exit(1)
        images = [img for img in images_str.splitlines() if "<none>" not in img]
        logger.info(f"Found {len(images)} Docker images to scan.")

    image_reports = []
    summary_table = []

    # --- Dashboard stats ---
    all_vulns = []
    severity_counts = {}
    package_type_counts = {}
    package_counts = {}
    cve_counts = {}

    # Parallel scan
    logger.info("Starting parallel scan of images...")
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(scan_image, image, temp_dir): image for image in images}
        for future in concurrent.futures.as_completed(futures):
            image = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                logger.error(f"Exception occurred while scanning image '{image}': {exc}")
                continue
            if result is None:
                logger.warning(f"Scan result for image '{image}' is None. Skipping.")
                continue
            image_report, summary_row = result
            image_reports.append(image_report)
            summary_table.append(summary_row)
            # For dashboards: collect all vulnerabilities
            for vuln in image_report['vuln_details']:
                all_vulns.append(vuln)
                sev = vuln['severity']
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                # Package type (e.g. "ubuntu" from "ubuntu:noble:libpam0g")
                pkg_type = vuln['package'].split(':')[0] if ':' in vuln['package'] else vuln['package']
                package_type_counts[pkg_type] = package_type_counts.get(pkg_type, 0) + 1
                # Top packages
                package_counts[vuln['package']] = package_counts.get(vuln['package'], 0) + 1
                # Top CVEs
                for cve in vuln.get('cve_list', []):
                    cve_id = cve['id']
                    cve_counts[cve_id] = cve_counts.get(cve_id, 0) + 1
            total_critical += summary_row['critical']
            total_high += summary_row['high']
            total_medium += summary_row['medium']
            total_low += summary_row['low']
            total_unknown += summary_row['unknown']

    # Sort image_reports and summary_table for consistent navigation
    image_reports.sort(key=lambda x: x['image'])
    summary_table.sort(key=lambda x: x['image'])

    # Prepare dashboard stats
    total_vulns = len(all_vulns)
    top_packages = sorted(package_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_cves = sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    dashboard_stats = {
        "total_vulns": total_vulns,
        "severity_counts": severity_counts,
        "package_type_counts": package_type_counts,
        "top_packages": top_packages,
        "top_cves": top_cves,
    }

    logger.info("Rendering HTML report using Jinja2 template...")
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
        dashboard_stats=dashboard_stats,
    )

    with open(html_report, "w") as f:
        f.write(rendered)
    logger.info(f"Report generated: {html_report}")

    logger.info("Cleanup temporary files...")
    shutil.rmtree(temp_dir)
    logger.info("Temporary files cleaned up. Scan complete.")

if __name__ == "__main__":
    main()
