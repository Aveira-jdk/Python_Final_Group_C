from selenium import webdriver
from selenium.webdriver.common.by import By

# Define the URL pattern for the website
vulmon_url_pattern = "https://vulmon.com/vulnerabilitydetails?qid={cve_id}&scoretype=cvssv3"


def vulmon_exploit_list_desc(cve_id):
    # Set Firefox options
    firefox_options = webdriver.FirefoxOptions()
    firefox_options.headless = True

    # Set up Firefox WebDriver with headless mode
    driver = webdriver.Firefox(options=firefox_options)

    try:
        # Construct the URL with the provided CVE ID
        url = vulmon_url_pattern.format(cve_id=cve_id)

        # Open the URL
        driver.get(url)

        # Wait for the content to be loaded
        content_element = driver.find_element(By.XPATH, '/html/body/div[3]/div/div[1]/div[5]')

        # Print the content
        print(content_element.text)

    except Exception as e:
        print("Error:", e)
    finally:
        # Close the browser
        driver.quit()


if __name__ == "__main__":
    cve_id = input("Enter the CVE ID: ").strip()
    vulmon_exploit_list_desc(cve_id)
