import requests
import pandas as pd
from bs4 import BeautifulSoup

def search_nvd_vulnerabilities(keyword):
    results = []
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}'

    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise HTTPError for bad responses
        data = response.json()

        if 'vulnerabilities' in data:
            vulnerabilities = data['vulnerabilities']
            for item in vulnerabilities:
                cve = item['cve']
                cve_id = cve.get('id', 'No data')
                source_identifier = cve.get('sourceIdentifier', 'No data')
                published = cve.get('published', 'No data')
                last_modified = cve.get('lastModified', 'No data')
                vuln_status = cve.get('vulnStatus', 'No data')

                descriptions = cve.get('descriptions', [])
                description_en = next((desc['value'] for desc in descriptions if desc['lang'] == 'en'), 'No description')
                description_es = next((desc['value'] for desc in descriptions if desc['lang'] == 'es'), 'No description')

                metrics = cve.get('metrics', {})
                cvss_v2_data = metrics.get('cvssMetricV2', [{}])[0].get('cvssData', {})
                cvss_v3_data = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})

                weaknesses = cve.get('weaknesses', [])
                weakness_desc = [desc['value'] for weakness in weaknesses for desc in weakness.get('description', [])]

                configurations = item.get('configurations', {}).get('nodes', [])
                cpe_list = []
                for config in configurations:
                    for cpe_match in config.get('cpeMatch', []):
                        cpe_list.append(cpe_match['criteria'])

                references = cve.get('references', [])
                reference_tags = [tag for ref in references for tag in ref.get('tags', [])]

                results.append({
                    'CVE ID': cve_id,
                    'Source Identifier': source_identifier,
                    'Published': published,
                    'Last Modified': last_modified,
                    'Vulnerability Status': vuln_status,
                    'Description (EN)': description_en,
                    'Description (ES)': description_es,
                    'CVSS v2 Source': cvss_v2_data.get('source', 'No data'),
                    'CVSS v2 Type': cvss_v2_data.get('type', 'No data'),
                    'CVSS v2 Version': cvss_v2_data.get('version', 'No data'),
                    'CVSS v2 Vector String': cvss_v2_data.get('vectorString', 'No data'),
                    'CVSS v2 Access Vector': cvss_v2_data.get('accessVector', 'No data'),
                    'CVSS v2 Access Complexity': cvss_v2_data.get('accessComplexity', 'No data'),
                    'CVSS v2 Authentication': cvss_v2_data.get('authentication', 'No data'),
                    'CVSS v2 Confidentiality Impact': cvss_v2_data.get('confidentialityImpact', 'No data'),
                    'CVSS v2 Integrity Impact': cvss_v2_data.get('integrityImpact', 'No data'),
                    'CVSS v2 Availability Impact': cvss_v2_data.get('availabilityImpact', 'No data'),
                    'CVSS v2 Base Score': cvss_v2_data.get('baseScore', 'No data'),
                    'CVSS v2 Base Severity': cvss_v2_data.get('baseSeverity', 'No data'),
                    'CVSS v2 Exploitability Score': cvss_v2_data.get('exploitabilityScore', 'No data'),
                    'CVSS v2 Impact Score': cvss_v2_data.get('impactScore', 'No data'),
                    'CVSS v2 AC Insufficient Info': cvss_v2_data.get('acInsufInfo', 'No data'),
                    'CVSS v2 Obtain All Privilege': cvss_v2_data.get('obtainAllPrivilege', 'No data'),
                    'CVSS v2 Obtain User Privilege': cvss_v2_data.get('obtainUserPrivilege', 'No data'),
                    'CVSS v2 Obtain Other Privilege': cvss_v2_data.get('obtainOtherPrivilege', 'No data'),
                    'CVSS v2 User Interaction Required': cvss_v2_data.get('userInteractionRequired', 'No data'),
                    'CVSS v3 Source': cvss_v3_data.get('source', 'No data'),
                    'CVSS v3 Type': cvss_v3_data.get('type', 'No data'),
                    'CVSS v3 Version': cvss_v3_data.get('version', 'No data'),
                    'CVSS v3 Vector String': cvss_v3_data.get('vectorString', 'No data'),
                    'CVSS v3 Base Score': cvss_v3_data.get('baseScore', 'No data'),
                    'CVSS v3 Severity': cvss_v3_data.get('baseSeverity', 'No data'),
                    'Weaknesses': ', '.join(weakness_desc) if weakness_desc else 'No data',
                    'CPE Configurations': ', '.join(cpe_list) if cpe_list else 'No data',
                    'Reference Tags': ', '.join(reference_tags) if reference_tags else 'No data'
                })
        else:
            print("No vulnerabilities found for the given keyword.")
    except requests.RequestException as e:
        print(f"An error occurred while fetching data from the NVD API: {e}")

    return results

def fetch_jvn_vulnerabilities(keyword):
    base_url = "https://jvndb.jvn.jp"
    search_url = f"{base_url}/search/index.php?mode=_vulnerability_search_IA_VulnSearch&lang=en&keyword={keyword}&useSynonym=1&vendor=&product=&datePublicFromMonth=&datePublicFromYear=&datePublicToMonth=&datePublicToYear=&dateLastPublishedFromMonth=&dateLastPublishedFromYear=&dateLastPublishedToMonth=&dateLastPublishedToYear=&cwe=&searchProductId="

    try:
        response = requests.get(search_url)
        response.raise_for_status()  # Raise an error for bad status codes
        soup = BeautifulSoup(response.text, 'html.parser')
        result_links = soup.find_all('a', href=True)
        vulnerability_urls = [base_url + link['href'] for link in result_links if "/en/contents/" in link['href']]

        for idx, vuln_url in enumerate(vulnerability_urls):
            filename = f"jvn_result_{idx+1}.txt"
            fetch_and_save_readable_text(vuln_url, filename)
            print(f"Saved: {filename}")
    except requests.RequestException as e:
        print(f"An error occurred while fetching data from the JVN site: {e}")

def fetch_and_save_readable_text(url, filename):
    try:
        page_response = requests.get(url)
        page_response.raise_for_status()
        soup = BeautifulSoup(page_response.text, 'html.parser')
        text_content = soup.get_text(separator='\n', strip=True)
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(text_content)
    except requests.RequestException as e:
        print(f"An error occurred while fetching page content from {url}: {e}")

if __name__ == "__main__":
    keyword = input("Enter a keyword to search for vulnerabilities (e.g., product name): ")
    keyword_encoded = keyword.replace(" ", "%20")  # URL encode the keyword for spaces

    # Fetch NVD vulnerabilities
    nvd_results = search_nvd_vulnerabilities(keyword_encoded)
    if nvd_results:
        combined_results = pd.DataFrame(nvd_results)
        # Insert keyword as a header row
        combined_results = pd.concat([pd.DataFrame([{'Keyword': keyword}]), combined_results], ignore_index=True)
        excel_file_path = 'vulnerability_results.xlsx'
        combined_results.to_excel(excel_file_path, index=False)
        print(f"NVD results saved to {excel_file_path}")
    else:
        print("No results found in NVD or an error occurred.")

    # Fetch JVN vulnerabilities
    fetch_jvn_vulnerabilities(keyword_encoded)
    print("JVN results saved in text files.")



