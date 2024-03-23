# CVE Information Scraper

This Python script is designed to scrape CVE (Common Vulnerabilities and Exposures) information from the National Vulnerability Database (NVD) and Exploit Database. It provides functionality to generate reports in both DOCX and JSON formats.

## Prerequisites
- Python 3.x installed
- Selenium library installed (`pip install selenium`)
- `geckodriver` for Firefox WebDriver installed and added to PATH ([Download geckodriver](https://github.com/mozilla/geckodriver/releases))

## Usage
1. Clone or download the repository to your local machine.
2. Install the required dependencies mentioned in the *Prerequisites* section.
3. Run the script using the command: `python cve_scraper.py`.
4. Follow the prompts to enter the CVE ID(s) and choose options accordingly.

## Functionality
- **CVE Information Retrieval:** Retrieves CVE information such as summary, CVSS score, vector, and reference from the NVD.
- **Exploit Database Check:** Checks for available exploits related to the provided CVE ID(s) from Exploit Database.
- **Report Generation:**
  - Generates a DOCX report containing CVE information and exploit links.
  - Exports CVE information and exploit links to a JSON file.
- **Automatic Tab Opening:** Automatically opens tabs in the default web browser for NVD and Exploit Database pages related to the provided CVE ID(s).

## Authors
- **Mahammad** - NVD scraper
- **Ravan** - Exploit-DB scraper, tab opener
- **Aytan** - DOCX report generation, tab opener
- **Nuray** - JSON export

## Contributing
Contributions are welcome. Feel free to fork the repository and submit pull requests.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
