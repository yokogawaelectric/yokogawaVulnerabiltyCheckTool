README

![image](https://github.com/yokogawaelectric/yokogawaVulnerabiltyCheckTool/assets/171666782/c70715a3-fe61-43d1-9a84-191a844e166b)

            Yokogawa Vulnerability Check tool



Overview
The Yokogawa Vulnerability Check tool allows users to identify known vulnerabilities associated with specific hardware or software. By providing the name of a hardware component, software application, or vendor, the tool fetches relevant vulnerability data and generates reports in both Excel and TXT formats.

Features
Input: Hardware name, software name, or vendor name.
Output: Vulnerabilities list in Excel and TXT formats.

Prerequisites:
Python: Ensure Python is installed on your system. You can download and install Python from python.org.
Git: Clone the repository using Git.
Installation and Setup
Clone the Repository

Open a terminal or command prompt and execute:
git clone https://github.com/yokogawaelectric/yokogawaVulnerabiltyCheckTool.git 
cd your-repository

Install Dependencies
Navigate to the repository directory and install the necessary Python packages using:
pip install -r requirements.txt
 
![image](https://github.com/yokogawaelectric/yokogawaVulnerabiltyCheckTool/assets/171666782/dcfc6ee9-a3f6-40f8-a47a-e1b91936aa34)



Usage
Run the Tool: Execute the Python script:
python yokogawa_vulnerabiility_check.py

![image](https://github.com/yokogawaelectric/yokogawaVulnerabiltyCheckTool/assets/171666782/5518e932-b959-454d-8bb7-5ff0af859b5a)

 

Provide Input: When prompted, enter the name of the hardware, software, or vendor.
Generate Report: The tool will process the input and produce vulnerability reports in both Excel and TXT formats.

Output
Excel Report: Contains a detailed list of vulnerabilities.
TXT Report: Provides a textual summary of vulnerabilities.

License
This project is licensed under the MIT License. See the LICENSE file for details.

Contributing
If you have suggestions or improvements, feel free to create a pull request or open an issue in the GitHub repository.

Contact
For any questions or support, please contact your.email@example.com.

Sources
This tool references data from the following sources:
JVN (Japan Vulnerability Notes): https://jvndb.jvn.jp/en/
NVD (National Vulnerability Database): https://nvd.nist.gov/vuln
Note: Ensure you have the required permissions to access the repository and files.
If you encounter any issues, please review the prerequisites and installation steps. For further assistance, consider opening an issue on GitHub.
