# CVE Information Scraper and Report Generator

### Project Description
This Python script allows users to scrape information related to Common Vulnerabilities and Exposures (CVE) from various sources such as NVD (National Vulnerability Database), Exploit-DB, Vulmon and CVE Details. It generates comprehensive reports in various formats including DOCX, JSON, PDF, Markdown(".md"), and HTML.

Additionally, this project has "file-options" version, which allows users to choose the export format as they wish instead of exporting to all possible formats at once.

### Dependencies
* Python 3.x
* Selenium
* os
* re
* json
* docx
* fpdf
* time
* webbrowser

### Instructions for Running the Project
1. Clone or download the repository containing the Python script.
2. Install the required dependencies using pip:
**Windows:**
`pip install selenium python-docx fpdf`

**Linux:**
`pip3 install selenium python-docx fpdf`

We can also install dependencies using requirements.txt

`pip install -r requirements.txt`

3. Ensure you have a compatible web browser installed (currently configured for Firefox, but can be changed).
4. Run the Python script cve_scraper.py using the following command :

**For Windows:**
`python cve_scraper.py`

**For GNU/Linux:**
`python3 cve_scraper.py`


5. Follow the prompts to input the CVE ID and generate reports.
### Group Members and Roles
**Mahammad**
#### Responsibilities:
* Implemented the NVD scraper functionality for extracting vulnerability information.
* Developed the HTML exporter module for generating HTML reports.
* Developed the exploit list scraper from Vulmon which is currently inactive due to uselessness, but it's still functioning.
* Developed to the main function.
* Developed second version of main function which allows the user to choose the file extension to export

**Nuray**
#### Responsibilities:
* Implemented the JSON exporter module for exporting data in JSON format.
* Developed the CVE existence checker to verify the validity of CVE IDs.

**Aytan**
#### Responsibilities:
* Implemented the DOCX exporter module for generating reports in DOCX format.
* Developed the PDF exporter module for generating PDF reports.

**Ravan**
#### Responsibilities:
* Implemented the Exploit-DB scraper module for retrieving exploit information.
* Developed the Markdown exporter module for generating reports in Markdown format.
* Prepared the general project report and README file

## License

This project is licensed under the GNU GENERAL PUBLIC LICENSE License - see the [LICENSE](LICENSE) file for details.
