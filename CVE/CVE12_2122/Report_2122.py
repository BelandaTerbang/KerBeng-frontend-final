from Metode import *

class CReport(Report):

    def __init__(self):
        super().__init__()
        
    def initData(self):
        print(f"self-data-report {self._dataReport}")
        # Ambil daftar IP dan abaikan key 'vulnList' dan 'mysql'
        for key, value in self._dataReport.items():
            if key in ('vulnList', 'mysql'):
                continue

            ip = key
            port = value.get('port')
            service = value.get('service')
            version = value.get('version')
            is_vulnerable = [ip, port] in self.dataReport.get('vulnList', [])

            self._data = {
                'IP': ip,
                'Port': port,
                'Service': service,
                'Version': version,
                'Vulnerable': is_vulnerable
            }
            print(f"dataDalam: {self._data}")

    def add_header(self):
        # Add Header
        header_section = self._document.sections[0]
        header = header_section.header
        header_paragraph = header.paragraphs[0]
        header_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.LEFT
        
        # Add the logo
        logo_path = "Logo Horizontal.png"
        logo_height = Cm(1.5)
        run = header_paragraph.add_run()
        run.add_picture(logo_path, height=logo_height)
        
        # Add space after header
        header.add_paragraph()

    def creat_cover_page(self):
        # Add the logo image
        #self._document.add_picture('ugm.png', width=Inches(2))
        #self._document.paragraphs[-1].alignment = WD_PARAGRAPH_ALIGNMENT.CENTER  # Center align the image
        
        # Add spacer
        self._document.add_paragraph()
        self._document.paragraphs[-1].add_run().add_break()
        
        while len(self._document.paragraphs) % 4 != 0:
            self._document.add_paragraph()
        
        title = """Client Report – MySQL Authentication Bypass (CVE-2012-2122)"""
        self._document.add_heading(title, level=0).alignment = WD_PARAGRAPH_ALIGNMENT.CENTER  # Center align the text
        
        # Add spacer
        self._document.add_paragraph()
        self._document.paragraphs[-1].add_run().add_break()
        
        while len(self._document.paragraphs) % 12 != 0:
            self._document.add_paragraph()
        
        # Add details
        text = f"""
        Company: Penelitian Damas 2024
        Authors: N.R. Rosyid, Y. M. Saputra, Anni K. Fauziyah, Yoan Navie Ananda
        Date: {date.today().strftime('%d %B %Y')}
        Version 1.0"""
        self._document.add_paragraph(text)
        self._document.add_page_break()
        
    def add_introduction(self):
        self._document.add_heading('1. Executive Summary', level=2)
        pendahuluan_paragraph = self._document.add_paragraph()
        #pendahuluan_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.JUSTIFY  # Rata kanan-kiri
        pendahuluan_text = (
            f"This report provides the results of a security assessment conducted on the {self._data['Service']} service running on host {self._data['IP']}. The system was identified to be running {self._data['Service']} version {self._data['Version']}, which is affected by a known critical authentication bypass vulnerability (CVE-2012-2122). The vulnerability allows unauthenticated attackers to gain root access to the {self._data['Service']} service without knowing the correct password."
        )
        pendahuluan_paragraph.add_run(pendahuluan_text)

    def add_scope(self): # Deskripsi Kerentanan
        self._document.add_heading('2. Vulnerability Overview – CVE-2012-2122', level=1)
        ruang_lingkup_paragraph = self._document.add_paragraph()
        #ruang_lingkup_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.JUSTIFY  # Rata kanan-kiri
        ruang_lingkup_text = (
            "CVE ID: CVE-2012-2122\n"
            "Tipe: Authentication Bypass\n"
            "CVSS v2: 7.5 (High)\n"
            "Description:\n"
            "A logic flaw in MySQL's authentication mechanism allows an attacker to login with an incorrect password under certain conditions. Specifically, due to the way the memcmp() function processes authentication hashes, invalid passwords have a 1 in 256 chance of being accepted.\n"
            "\nAffected Versions:\n"
            "- MySQL < 5.1.63\n"
            "- MySQL < 5.5.24\n"
            "- MariaDB < 5.5.23\n\n"
            "References:\n"
            "- https://nvd.nist.gov/vuln/detail/CVE-2012-2122\n"
            "- https://www.exploit-db.com/exploits/19091"
        )
        ruang_lingkup_paragraph.add_run(ruang_lingkup_text)

    def add_methodelogy(self):
        self._document.add_heading('3. Assessment Approach', level=1)
        metodologi_paragraph = self._document.add_paragraph()
        #metodologi_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.JUSTIFY # Rata kanan-kiri
        metodologi_text = (
            "The assessment involved:\n"
            "Phase 1 – Scanning:\n"
            "Service discovery and fingerprinting using Nmap tool:\n"
            f"nmap -sV -sC -Pn -O -oN nmap_results.txt {self._data['IP']}\n\n"
            "Phase 2 – Enumeration:\n"
            "Version enumeration of the MySQL service.\n\n"
            "Phase 3 – Version Analysis:\n"
            "Validation of vulnerability presence based on known affected verseions\n\n"
            "Phase 4 – Exploitation:\n"
            "Proof-o-Concept (PoC) exploitation to confirm unauthorized access and send SQL Command SHOW DATABASES;\n\n"
            "Tools used include Nmap and a custom brute-force script for CVE-2012-2122 verification."
        )
        metodologi_paragraph.add_run(metodologi_text)

    def add_vulnerability_ident(self):
        self._document.add_heading('4. Key Findings', level=1)
        identification_paragraph = self._document.add_paragraph()
        #identification_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.JUSTIFY # Rata kanan-kiri
        table = self._document.add_table(rows=6, cols=2)
        table.style = 'Table Grid'
        data = [
            ("Target Host", f"{self._data['IP']}"),
            ("Open Port", f"{self._data['Port']}/tcp"),
            ("Service", f"{self._data['Service']}"),
            ("Detected Version", f"{self._data['Version']}"),
            ("Vulnerability Status", "Confirmed Exploitable"),
            ("Login Attempt Count", "409 attempts before successful login"),
        ]

        for i, row in enumerate(data):
            table.cell(i, 0).text = row[0]
            table.cell(i, 1).text = row[1]
        identification_text = (
            "Upon successful exploitation, the following databases were enumerated: information _schema, mysql, performance_schema, test."
        )
        identification_paragraph.add_run(identification_text)

    def add_vulnerability_scanning(self):
        self._document.add_heading('5. Analysis', level=1)
        scanning_paragraph = self._document.add_paragraph()
        #scanning_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.JUSTIFY  # Rata kanan-kiri
        scanning_text = (
            f"The target was identified as running {self._data['Service']} version {self._data['Version']}, which matches the list of vulnerable versions for CVE-2012-2122. Exploitation results show that an attacker can gain root access through random brute-force attempts, without a valid password, and successfully execute SQL commands."
        )
        scanning_paragraph.add_run(scanning_text)

    def add_vulnerability_exploit(self):
        self._document.add_heading('6. Risk Impact', level=1)
        exploitation_paragraph = self._document.add_paragraph()
        #exploitation_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.JUSTIFY  # Rata kanan-kiri
        exploitation_text = (
            "An attacker who successfully exploits this vulnerability can gain administrative access to the database system. This can result in:\n"
            "- Unauthorized access and modification of sensitive data.\n"
            "- Lateral movement within the internal network.\n"
            "- System compromise and data exfiltration.\n"
            "Given the ease of exploitation and potential damage, this vulnerability is classified as High Risk."
        )
        exploitation_paragraph.add_run(exploitation_text)

    def add_recommendation(self):
        self._document.add_heading('7. Recommendatioins and Conclution', level=1)
        recommendations_paragraph = self._document.add_paragraph()
        #recommendations_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.JUSTIFY  # Rata kanan-kiri
        recommendations_text = (
            "To mitigate this vulnerability, we recommend the following actions:\n"
            f"1. Immediately upgrade {self._data['Service']} to version {self._data['Version']} or later:\n"
            "   - MySQL ≥ 5.5.24\n"
            "   - MariaDB ≥ 5.5.24\n"
            f"2. Restrict remote access to {self._data['Service']} (port {self._data['Port']}) to trusted IP addresses only.\n"
            "3. Enable detailed logging and monitor for unusual access patterns.\n"
            "4. Implementation firewall or fail2ban for blocking brute-force login attempts.\n"
            "5. Posibly implement socket authentitation (unix_socket) in local system.\n\n"
            "The presence of CVE-2012-2122 on the MySQL service of the assessed host poses a significant security risk. Timely patching and access control measures are essential to prevent unauthorized access and data breaches."
        )
        recommendations_paragraph.add_run(recommendations_text)


        self._document.add_heading('8. Referensi Teknis', level=1)
        referensi_paragraph = self._document.add_paragraph()
        referensi_text = (
            "- CVE-2012-2122 – https://nvd.nist.gov/vuln/detail/CVE-2012-2122\n"
            "- Exploit PoC – https://www.exploit-db.com/exploits/19091\n"
            "- Oracle Patch Note – https://www.oracle.com/security-alerts/cpujul2012.html"
        )
        referensi_paragraph.add_run(referensi_text)