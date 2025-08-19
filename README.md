# DOM-XSS-Finder 🔍

A lightweight Python tool for scanning JavaScript/HTML files to detect potential DOM-based XSS sinks.

This script parses a list of URLs, fetches their content, and searches for known DOM XSS sink functions/properties.  
It highlights high, medium, and low severity findings, helping you quickly identify dangerous patterns that may lead to DOM-based cross-site scripting vulnerabilities.  

⚠️ Note
This tool detects potential sinks. A match does not always mean exploitable XSS.
You must manually verify if the data flowing into the sink is attacker-controlled and whether proper sanitization exists.

---

## ✨ Features
- Detects real DOM XSS sinks such as:
  - innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, `eval`, `new Function`
  - jQuery sinks like .html()`, `.append()`, `.prepend()`
  - location.href`, `document.location`, `top.location`
  - Dynamic .src=` assignments
- Results are **tagged by severity**: [HIGH]`, `[MEDIUM]`, `[LOW]`
- Uses **multi-threading** for faster scanning (-t` option)
- **Handles redirects** automatically
- Falls back to **POST requests** if GET returns 401/403
- Writes results to file immediately with -o`

---

## ⚙️ Installation
Clone the repo and install dependencies:

git clone https://github.com/greenghostOG/dom-xss-finder.git
cd dom-xss-finder
pip install -r requirements.txt
If env error occurs try : pip install -r requirements.txt --break-system-packages
Requirements:

Python 3.7+

requests (installed via requirements.txt)

🚀 Usage
1. Prepare a URL list
Put all target URLs (e.g. JS files, HTML pages, endpoints) into a text file, one per line:


https://target.com/app.js
https://target.com/page.html
https://target.com/static/script.js
2. Run the scanner

python dom.py -l urls.txt -o results.txt -t 20
-l → input file containing URLs

-o → (optional) save results to output file

-t → number of threads (default 10, higher = faster)

3. Example output

[+] Scanning https://target.com/app.js
[VULN] [HIGH] https://target.com/app.js -> \binnerHTML\b :: div.innerHTML = userInput;
[VULN] [MEDIUM] https://target.com/page -> location.href :: location.href = queryParam;
[VULN] [LOW] https://target.com/lib.js -> .src= :: script.src = value;
The same results will also be appended to your output file (results.txt if specified).

📖 How It Works
Fetches target content (GET by default, falls back to POST for restricted pages).

Scans JavaScript/HTML using regexes for known DOM-XSS sinks.

Classifies results into:

HIGH → Direct code execution (innerHTML, eval, document.write, etc.)

MEDIUM → Navigation / redirect-based (location.href, setTimeout(string))

LOW → Less risky but still relevant (.src= assignments)

Reports findings live on screen and saves them to a file.

👨‍💻 Author Bhupender Kumar
Made for security researchers and bug bounty hunters who need a quick DOM-XSS sink scanner.
