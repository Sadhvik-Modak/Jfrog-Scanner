# Yeedu JFrog Docker Vulnerability Report

This tool scans Docker images for vulnerabilities using JFrog Xray and generates a modern, enterprise-grade HTML dashboard report.

---

## Features

- **Parallel scanning** of Docker images for fast results.
- **Enterprise-grade HTML dashboard** with interactive charts, summary tables, and detailed vulnerability breakdowns.
- **Clickable CVE badges** with direct links to NVD.
- **Severity color coding** and easy navigation between images.
- **Responsive, modern UI** for easy browsing and reporting.
- **Flexible image selection:**  
  Scan all local images or only specific images using the `--images` option.
- **Enhanced logging:**  
  Detailed progress and error logs for troubleshooting.

---

## Prerequisites

1. **Python 3.7+**  
2. **JFrog CLI**  
   Install from [https://jfrog.com/getcli/](https://jfrog.com/getcli/)
3. **Jinja2 Python package**  
   Install with:
   ```bash
   pip install -r requirements.txt
   ```
4. **Docker**  
   Ensure Docker is installed and running.

---

## Setup

1. **Configure JFrog CLI endpoint**  
   ```bash
   jf c add
   ```
   Follow the prompts to set up your JFrog/Xray connection.

2. **Clone or copy this repository**  
   ```bash
   git clone <this-repo-url>
   cd jfrog-scanner
   ```

---

## Usage

### Scan all local Docker images:
```bash
python3 docker-security-scan.py
```

### Scan only specific images:
```bash
python3 docker-security-scan.py --images repo1:tag1 repo2:tag2
```

### Example:
```bash
python3 docker-security-scan.py --images ubuntu:latest myapp:1.0
```

After completion, open the generated HTML file (e.g., `docker_security_scan_report_YYYYMMDD_HHMMSS.html`) in your browser.

---

## Output

- **Dashboard:** Pie and bar charts for overall and per-image vulnerability distribution.
- **Summary Table:** All images with counts by severity.
- **Per-Image Details:** Expandable tables with package, version, summary, fixed versions, CVEs (as clickable badges), and references.
- **Navigation:** Jump links and "Back to Top" for easy browsing.
- **Logs:** Detailed progress and error logs are printed to the console.

---

## Troubleshooting

- **No images found:**  
  Ensure you have local Docker images (`docker images`).

- **JFrog CLI not found:**  
  Install and configure JFrog CLI as described above.

- **Jinja2 not installed:**  
  Run `pip install -r requirements.txt`.

- **Docker not running:**  
  Start Docker and ensure you have permission to run Docker commands.

---

## Customization

- **Template:**  
  The HTML template is in `docker_security_scan_report_template.html`.  
  You can further customize branding, colors, or layout as needed.

- **Sample Scan Result:**  
  See `sample-simple-json-scan-result.json` for a sample scan output.

---

## License

MIT or your organization’s preferred license.

---

## Author

Yeedu Security Engineering Team

