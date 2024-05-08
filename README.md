# Group Name
Innovators
# Group Members
1. Nooralya Qasrina binti Zuraimi (2118228)
2. Siddiqui Maryam (2115928)
3. Yaya ali hassane (1928095)
# Assigned Tasks
1. Nooralya Qasrina binti Zuraimi (2118228)
   * Identify, evaluate and prevent of:
     * Secured Cookies
     * CSP
     * JS Library
     * Information Disclosure
2. Siddiqui Maryam (2115928)
   * Identify, evaluate and prevent of:
     * Cookie Poisioning 
     * Potential XSS
     * HTTPS Implementation (TLS/SSL) 
     * Information Disclosure
3. Yaya ali (1928095)
     * Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc)
     * Hash Disclosure
     * CSRF
     *
# Table of Contents
1. Description
2. Observation Results
    i. Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc)
    ii. Hash Disclosure
    iii. CSRF
Secured Cookies
CSP
JS Library
HTTPS implementation (TLS/SSL)
Cookie Poisoning
Potential XSS
Information Disclosure
# Description
Our assigned web application is the Selangor State Government (SUK) URL (https://www.selangor.gov.my/). In this case study, our group will look into the vulnerabilities of the web application by scanning the website using OWASP ZAP using both the automated scan and manual explore. We will mainly be focusing on automated scan due to the large amount of links and webpages the site has.

The alerts observed are listed on the table of contents and we will also identify the level of risk for each alert and additional information on the classification of threats (CWE or CVE).
# Observation Results
<h3>a. Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc)
  
 <br> Vulnerability 1: Server Leaks Version Information via "Server" HTTP Response Header Field
<img width="672" alt="Screenshot 2024-05-09 at 1 28 03 AM" src="https://github.com/alyaqasrina/Innovators-Group/assets/78656130/b0d05f7b-2fb5-4e76-8e88-2016dd4dad6f">

#### Identify Vulnerability:
<img width="375" alt="Screenshot 2024-05-09 at 1 28 54 AM" src="https://github.com/alyaqasrina/Innovators-Group/assets/78656130/683cab4f-37fe-457f-9f52-2974c8c8b742">

- **Description**: The web/application server is leaking version information via the "Server" HTTP response header.
- **Evidence**: The "Server" header in the HTTP response reveals the server's version (nginx/1.18.0) and operating system (Ubuntu).
- **Risk**: High confidence. Leaking server version information can facilitate attackers in identifying vulnerabilities.
- **Observation**: Passive identification through HTTP response headers.
- **Source**: Passive (10036 - HTTP Server Response Header)
- **Input Vector**: HTTP response headers
- **Other Info**: CWE ID: 200, WASC ID: 13
- **Alert Tags**:
  - OWASP_2021_A05
  - OWASP_2017_A06
  - WSTG-v42-INFO-02

#### Evaluate Vulnerability:
- **Potential Impact**: Attackers may exploit known vulnerabilities associated with the disclosed server version.
- **Classification of Threats**: CWE ID 200
- **Recommendation**: Configure the web server to suppress the "Server" header or provide generic details. Regularly update server software to patch known vulnerabilities. Implement security best practices recommended by OWASP and other security resources.
- **References**:
  - [Apache ServerTokens Directive](https://httpd.apache.org/docs/current/mod/core.html#servertokens)
  - [Microsoft Security Configuration](https://learn.microsoft.com/en-us/previous-versions/msp-n-p/ff648552(v=pandp.10))
  - [Troy Hunt's Article on Response Headers](https://www.troyhunt.com/shhh-dont-let-your-response-headers/)

#### Prevent Vulnerability:
1. **Configure Server Response Headers**: Follow the documentation provided by your server software (nginx in this case) to configure it to suppress the "Server" header or provide generic details.
2. **Regularly Update Server Software**: Ensure your server software is up to date with the latest patches and security fixes to mitigate known vulnerabilities.
3. **Implement Security Best Practices**: Continuously monitor and apply security best practices recommended by OWASP and other security resources to minimize the risk of exploitation.

### Vulnerability 2: Cross-Domain JavaScript Source File Inclusion
<img width="672" alt="Screenshot 2024-05-09 at 1 42 14 AM" src="https://github.com/alyaqasrina/Innovators-Group/assets/78656130/a198355b-d7c2-4fcd-8b78-8311a69df052">

#### Identify Vulnerability:

- **Description**: Cross-domain JavaScript source file inclusion.
- <img width="342" alt="Screenshot 2024-05-09 at 1 42 28 AM" src="https://github.com/alyaqasrina/Innovators-Group/assets/78656130/08e0e55b-ce41-4377-99b1-864d1e2b9042">
 **Evidence**: The HTML code includes script tags with `src` attributes pointing to external domains (`https://ajax.googleapis.com`).
- **Risk**: Allows attackers to inject malicious JavaScript code from external sources, leading to XSS attacks.
- **Observation**: The presence of external JavaScript source files being included in the HTML code.
- **Recommendation**: Evaluate the necessity of including external scripts and consider mitigating the risk by hosting essential scripts locally or from trusted sources.

#### Evaluate Vulnerability:
- **Potential Impact**: Allows attackers to inject malicious JavaScript code from external sources, leading to XSS attacks.
- **Recommendation**: Evaluate the necessity of including external scripts and consider mitigating the risk by hosting essential scripts locally or from trusted sources.

#### Prevent Vulnerability:
1. **Host Essential Scripts Locally**: If feasible, host critical JavaScript files locally to minimize reliance on external sources.
2. **Use Subresource Integrity (SRI)**: Implement SRI to ensure the integrity of external scripts by verifying their integrity hashes.
3. **Regularly Monitor External Dependencies**: Continuously monitor and update external scripts to mitigate the risk of compromise.







<h3>b. Hash Disclosure</h3>


<h3>c. CSRF</h3>


<h3>d. Secured Cokkies</h3>
<h4> Identify: </h4>
   + Identified as Cookie Without Secure Flag <be>
   + Risk: Low <br>
   - CWE ID 614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute) <br>  
   - WASC	ID 13 <br>
   - A cookie has been set without the secure flag, which means that the cookie can be accessed via unencrypted connections through Set-Cookie: jtqftknonmu7j3ncqf73knu18a <br>
<h4> Evaluate: </h4>
  

  



   
