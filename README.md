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
   * Identify, evaluate and prevent of:
     * Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc)
     * Hash Disclosure
     * CSRF
     * Information Disclosure
       
# Table of Contents

1. Description
2. Observation Results from:
   * Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc)
   * Hash Disclosure
   * CSRF
   * Secured Cookies
   * CSP
   * JS Library
   * HTTPS implementation (TLS/SSL)
   * Cookie Poisoning
   * Potential XSS
   * Information Disclosure
   
# Description
Our given web application is the  the Selangor State Government (SUK) (https://www.selangor.gov.my/). In this case study, our group is going to evaluate the web application's vulnerabilities by scanning the website with OWASP ZAP, both automatically and manually. We will primarily focus on automated scanning due to the site's enormous number of links and sites.

The observed alerts are presented in the table of contents, and we will additionally show the level of risk for each alert as well as additional threat classification information (CWE/CVE).

# Observation Results

<h3>a. Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc)</h3>
 <br> i. Server Leaks Version Information via "Server" HTTP Response Header Field
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

### Cross-Domain JavaScript Source File Inclusion
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


<h3>c. Hash Disclosure</h3>

Upon conducting a detailed assessment of the Selangor State Government website, we found no instances of hash disclosure. This means that sensitive information like passwords or cryptographic hashes is not exposed. While hash disclosure vulnerabilities can be serious, potentially allowing attackers to access and manipulate sensitive data, the absence of such vulnerabilities here indicates robust security measures.

### lack of authentication 
It's worth noting that the website doesn't require users to log in or authenticate themselves. While authentication is crucial for verifying users' identities and controlling access to sensitive data, its absence here suggests that the website mainly serves as an informational platform. This might increase concerns about data security, but for a public-facing website providing general information, the lack of authentication isn't necessarily a flaw.

<h3>c. CSRF</h3>

### Vulnerability : Lack of Anti-CSRF Tokens
<img width="1005" alt="Screenshot 2024-05-09 at 2 06 47 AM" src="https://github.com/alyaqasrina/Innovators-Group/assets/78656130/4fabe023-1f63-48dd-a83b-84e42e9e7065">

#### Identification:
- **Description**: The absence of Anti-CSRF tokens in an HTML submission form was detected.
- **Evidence**: An HTML form with the action `/index.php/pages/module_search` lacks Anti-CSRF tokens, making it vulnerable to CSRF attacks.
- **Risk Assessment**: The risk associated with this vulnerability is considered medium, with confidence rated as low. CSRF attacks can manipulate authenticated users into executing unintended actions.
- **Observation**: This vulnerability was identified passively by examining the HTML form structure.
- **Input Vector**: CSRF attacks can exploit forms lacking Anti-CSRF tokens.
- **Other Information**: The Common Weakness Enumeration (CWE) ID for this vulnerability is 352, and the Web Application Security Consortium (WASC) ID is 9.

#### Evaluation:
- **Potential Impact**: Without Anti-CSRF tokens, attackers can perform unauthorized actions on behalf of authenticated users.
- **Recommendation**: Mitigate this vulnerability by integrating Anti-CSRF tokens into HTML forms. Utilize established libraries or frameworks like OWASP CSRFGuard to enhance protection. Ensure thorough scrutiny for cross-site scripting (XSS) vulnerabilities, as they can circumvent CSRF defenses.
- **References**:
  - [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
  - [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

#### Prevention Measures:
1. **Architecture and Design Phase**:
   - Employ trusted libraries or frameworks like OWASP CSRFGuard to manage CSRF vulnerabilities.
   - Implement the generation and validation of unique nonces for each form submission to mitigate CSRF attacks.
   - Identify critical operations and enforce separate confirmation requests to prevent unintended actions.
   - Utilize ESAPI Session Management control and avoid using the GET method for state-changing requests.
2. **Implementation Phase**:
   - Ensure the absence of XSS vulnerabilities within the application to prevent bypassing CSRF defenses.
   - Optionally, examine the HTTP Referer header to verify the request's origin, albeit with caution as it may disrupt legitimate functionalities.

#### Example Implementation:
```html
<form action="/index.php/pages/module_search" method="POST">
  <input type="hidden" name="csrf_token" value="unique_token_here">
  <button type="submit">Submit</button>
</form
```

<h3>d. Secured Cookies</h3>

#### Identify Vulnerability:
* Identified as Cookie Without Secure Flag 
* Risk Level: Low 
* CWE ID 614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute)   
* WASC ID 13
* **Alert Tags**
  * 	OWASP_2017_A06
  * 	OWASP_2021_A05
  * 	WSTG-V42-SESS-02
* A cookie has been set without the secure flag, which means that the cookie can be accessed via unencrypted connections through Set-Cookie: jtqftknonmu7j3ncqf73knu18a
  
#### Evaluate Vulnerability
The secure attribute is an option that can be set by the application server when sending a new cookie to the user within an HTTP Response. The purpose of the secure attribute is to prevent cookies from being observed by unauthorized parties due to the transmission of the cookie in clear text. When not implemented it permits sensitive information like user credentials, session tokens, and other sensitive information to be transmitted across unencrypted HTTP connections, leaving it vulnerable to interception by attackers. Hence, it can result in unauthorized access to sensitive data, session hijacking, malicious activity, and other security breaches.

Related CVE/CWE:
* CVE-2004-0462: A product does not set the Secure attribute for sensitive cookies in HTTPS sessions, which could cause the user agent to send those cookies in plaintext over an HTTP session with the product. CVSS Score is 2.1
* CVE-2008-3663: A product does not set the secure flag for the session cookie in an HTTPS session, which can cause the cookie to be sent in HTTP requests and make it easier for remote attackers to capture this cookie. CVSS Score is 5.0
* CVE-2008-3662: A product does not set the secure flag for the session cookie in an HTTPS session, which can cause the cookie to be sent in HTTP requests and make it easier for remote attackers to capture this cookie. CVSS Score is 5.0
* CVE-2008-0128: A product does not set the secure flag for a cookie in an HTTPS session, which can cause the cookie to be sent in HTTP requests and make it easier for remote attackers to capture this cookie. CVSS Score is 5.0

#### Prevent Vulnerability:
* The secure flag should be set on all cookies for transmitting sensitive data when accessing content over HTTPS. Suppose cookies are used to transmit session tokens. In that case, areas of the application that are accessed over HTTPS should employ their session handling mechanism, and the session tokens used should never be transmitted over unencrypted communications.

#### References
* https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html
* https://cwe.mitre.org/data/definitions/614.html
* https://portswigger.net/kb/issues/00500200_tls-cookie-without-secure-flag-set
* https://www.zaproxy.org/docs/alerts/10011/

<h3> e. CSP </h3>

#### Identify Vulnerability

Based on (https://www.selangor.gov.my/), there are four CSP-related vulnerabilities found as stated below: 
* CSP: Wildcard Directive <br>
A wildcard directive is a CSP rule that allows any content source to be loaded by a web application, making it vulnerable to various attacks. <br>
* script-src unsafe-inline <br>
The 'script-src' directive specifies valid sources for JavaScript. The 'unsafe-inline' directive allows the use of inline resources, such as inline "<script>" and "<style>" elements, 'javascript' URLs and inline event handlers. This means that any places where a user can inject a script attribute into the website. <br>
* CSP: style-src unsafe-inline <br>
It indicates that the website’s Content Security Policy(CSP) allows the use of inline styles, which can be exploited by attackers.<br>
* Content Security Policy (CSP) Header Not Set <br>
Without a CSP header, your website is vulnerable to XSS attacks, where an attacker can inject malicious scripts into your web pages and steal sensitive user information or perform unauthorized actions on behalf of the user. <br>
* Risk level: Medium 
* CWE ID 639 (Protection Mechanism Failure)   
* WASC ID 15
* **Alert Tags**
  * OWASP_2017_A06
  * OWASP_2021_A05

#### Evaluate Vulnerability
Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files. <br>

CWE ID 693 refers to the absence or incorrect use of a protection mechanism that provides sufficient defense against directed attacks against the website. This vulnerability includes three distinct situations which are:
* A "missing" protection mechanism occurs when the application does not define any mechanism against a certain class of attack.
* An "insufficient" protection mechanism might provide some defenses - for example, against the most common attacks - but it does not protect against everything that is intended.
* An "ignored" mechanism occurs when a mechanism is available and in active use within the product, but the developer has not applied it in some code path.

#### Prevent Vulnerability

* **Deny-All Policy** = Create a CSP that disables all external resources by default. Then, progressively include specific allowances for trusted sources via directives such as script-src and style-src. The "deny-all, then allow" method reduces the attack surface.
* **Minimize Wildcards** = While wildcards (*) can seem convenient, they can introduce vulnerabilities. Use them cautiously and only for trusted CDNs (Content Delivery Networks) or subdomains under your control. Consider specific domain names or source hashes for better security.
* **Report-Only Mode** = Before deploying a finalized CSP, implement it in report-only mode. This allows the browser to identify and report any blocked requests in the console without impacting website functionality. You can then analyze the blocked requests and refine your CSP accordingly.
* Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

#### References
* https://cwe.mitre.org/data/definitions/693.html
* https://www.zaproxy.org/docs/alerts/10055-5/
* https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
* https://portswigger.net/web-security/cross-site-scripting/content-security-policy
* https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

<h3>f. JS Library</h3>

#### Identify Vulnerability:

* Identified as Vulnerable JS Library 
* Risk Level: Medium
* CWE ID 829 (Inclusion of Functionality from Untrusted Control Sphere)   
* The identified library ExampleLibrary, version x.y.z is vulnerable.
* **Alert Tags**
  * OWASP_2017_A09
  * OWASP_2021_A06

#### Evaluate Vulnerability:

* When using third-party functionality, such as a web widget, library, or other source of functionality, the product must effectively trust it. Without proper protective techniques, the feature could be harmful (either from an untrusted source, faked, or modified in transit from a trusted source). The functionality may also have inherent flaws or provide access to additional functionality and state information that should be kept private to the base system, such as system state information, sensitive application data, or a web application's DOM.

* For example, the identified ExampleLibrary (version x.y.z) poses a security risk due to CWE-829 (Inclusion of Functionality from Untrusted Control Sphere). CWE-829 vulnerabilities are primarily caused by improper input sanitization, which means that if the library fails to appropriately sanitize user-provided data before using it, attackers can inject malicious scripts. These scripts can then be performed within the context of the website, potentially resulting in Cross-Site Scripting (XSS) assaults and other malicious activities such as website defacement or server-side attacks. Another factor could be unsafe dynamic code evaluation, which means that the library may allow the evaluation of code generated by user input. This provides another opportunity for attackers to inject malicious code that is executed. 

Related CVE/CWE: 
* **CVE-2010-2076** = Product does not properly reject DTDs in SOAP messages, which allows remote attackers to read arbitrary files, send HTTP requests to intranet servers, or cause a denial of service. CVSS Score is 7.5.
* **CVE-2004-0285** = Modification of assumed-immutable configuration variable in include file allows file inclusion via direct request. CVSS Score is 7.5.
* **CVE-2004-0128** = Modification of assumed-immutable variable in configuration script leads to file inclusion. CVSS Score is 7.5.
* **CVE-2005-1864** = PHP file inclusion. CVSS Score is 5.0.
* **CVE-2002-1704** = PHP remote file include. CVSS Score is 5.0.
* **CVE-2004-0127** = Directory traversal vulnerability in PHP include statement.CVSS Score is 7.5.
* **CVE-2005-3335** = PHP file inclusion issue, both remote and local; local include uses ".." and "%00" characters as a manipulation, but many remote file inclusion issues probably have this vector. CVSS Score is 7.5.

#### Prevent Vulnuerability

* Upgrade to the latest version of ExampleLibrary.
* To avoid CWE-602 (Client-Side Enforcement of Server-Side Security), ensure that any security checks done on the client side are mirrored on the server side. Attackers may bypass client-side checks by manipulating values after they have been done, or by changing the client to disable client-side checks entirely. The changed values would then be sent to the server.
* **Libraries or Framework** = Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
* **Attack Surface Reduction** = To prevent attackers from directly accessing the website's code, it's best to store library, include, and utility files outside the web document root (the publicly accessible folder). If it is not possible, keep them in a separate directory and restrict access using the web server's security features. A common approach involves creating a unique "secret" code within each program that uses the library. The library file itself then checks for this code. If the code isn't present, it means someone is trying to access the library directly (not through your program), and the library can shut down to avoid potential misuse.

#### References 

* https://cwe.mitre.org/data/definitions/829.html
* https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
* https://portswigger.net/support/using-burp-to-test-for-code-injection-vulnerabilities


<h3>g. HTTPS Implementation (TLS/SSL)</h3>

#### Identify Vulnerability:
  + OWASP ZAP does not contain any alerts, and neither can the risk level or CWE ID be found.

#### Evaluate Vulnerability:
- **Potential Impact**:
 Not accessible because this website has a https implementation, which is visible from the website's URL. Nevertheless, content that was originally seen using HTTPS (i.e., SSL/TLS encrypted) can also be viewed through HTTP (unencrypted).

#### Prevention Measures:
  Unavailable on the webpage. Making sure that the web server, application server, load balancer, etc. is set up to only serve such material via HTTPS is the solution to this alert, though. Think about 
  putting HTTP Strict Transport Security into practice.

<h3>h. Cookie Poisoning: </h3>

#### Identify Vulnerability:
- OWASP ZAP did not find any alerts. No danger level and CWE ID as a result.

#### Evaluate Vulnerability:
- **Potential Impact**:
- Not accessible via this website. However, this check looks for instances when cookie parameters may be changed by examining user input in query string parameters and POST data. This is referred to as a "cookie poisoning" attack, and it can be used if the attacker has the ability to modify the cookie in several ways. Although this might not always be exploitable, allowing URL parameters to set cookie values is typically regarded as problematic. 

#### Prevention Measures:
- Not accessible via this website. If not, allowing the user to change cookie names and values is the solution to this alert. Make sure semicolons are not utilised as name/value pair delimiters if query string parameters need to be included in cookie values.
- Using unique and secure session cookies. It's important to ensure that session identifiers are inaccessible to attackers once the session is closed. They should also be randomly generated and hard to crack by using brute force or other means.
- It is vital to use HTTPS communication to establish secure information flow and reduce the chances of attackers eavesdropping on cookie content.
- Reference: https://www.techtarget.com/searchsecurity/definition/cookie-poisoning

<h3>i. Potential XSS: </h3>

![image](https://github.com/alyaqasrina/Innovators-Group/assets/154775061/ddb4491c-1756-43be-b514-b6ba9cc4b93a)


#### Identify Vulnerability:

* User Controllable HTML Element Attribute (Potential XSS)
  * URL: https://www.selangor.gov.my/index.php/system/get_language_key
  * Risk level: Informational
  * CWE ID: 20
  * User-controlled HTML attribute values were found
  * **Alert Tags**:
      * OWASP_2021_A03
      * OWASP_2017_A01

#### Evaluate Vulnerability:
- **Potential Impact**:
- This check looks for places where particular HTML attribute values might be altered by examining user-supplied input in query string arguments and POST data.
- This offers cross-site scripting (XSS) hotspot identification; a security analyst will need to examine this further to assess its exploitability.
- Although there are several XSS-based attacks, they usually entail one of three tactics: redirecting the victim to the attacker's own website, manipulating the user's computer while pretending to be the vulnerable website, or transmitting sensitive information, like cookies or other session data, to the attacker.

#### Prevention Measures:
- Validate all input and sanitise output it before writing to any HTML attributes
- Try injecting special characters to see if XSS might be possible.
- Another way to protect against XSS attacks is output encoding. When you display dynamic content on your website (like user comments or messages), you need to encode it properly before rendering it in HTML.
- Reference: https://www.esecurityplanet.com/endpoint/prevent-xss-attacks/

<h3>j. Information Disclosure</h3>













   
