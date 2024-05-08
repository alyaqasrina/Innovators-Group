# Group Name
Innovators
# Group Members
1. Nooralya Qasrina binti Zuraimi (2118228)
2. Maryam
3. Yaya
# Assigned Tasks
1. Nooralya Qasrina binti Zuraimi (2118228)
   * Identify, evaluate and prevent of:
     * Secured Cookies
     * CSP
     * JS Library
     * Information Disclosure
2. Maryam
   *
     *
     *
     *
     *
3. Yaya
   *
     *
     *
     *
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
Our assigned web application is the Ministry of Higher Education (MOHE) website at https://www.mohe.gov.my/en. In this case study, our group will look into the vulnerabilities of the web application by scanning the website using OWASP ZAP using both the automated scan and manual explore. We will mainly be focusing on automated scan due to the large amount of webpages the site has.

The alerts observed are listed on the table of contents and we will also identify the level of risk for each alert and additional information on the classification of threats (CWE or CVE).
# Observation Results
<h3>a. Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc)<./h3>


<h3>b. Hash Disclosure</h3>


<h3>c. CSRF</h3>


<h3>d. Secured Cokkies</h3>
<h5> 1. Identify </h5>
   - Identified as Cookie Without Secure Flag <be>
   - Risk: Low <be>
   - CWE ID 614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute) <be>  
   - WASC	ID 13 <be>
   - A cookie has been set without the secure flag, which means that the cookie can be accessed via unencrypted connections through Set-Cookie: jtqftknonmu7j3ncqf73knu18a <be>
<h5> 2. Evaluate: </h5>

  



   
