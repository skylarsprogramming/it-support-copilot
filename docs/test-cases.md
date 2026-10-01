ID
Mode
Input / action
Expected
Actual
Pass
T01
Troubleshoot
Normal run on own laptop
Mostly green, BitLocker yellow without admin rights


T02
Troubleshoot
Real wrong DNS server (5.2)
DNS and internet red, AI names DNS as the cause


T03
Troubleshoot
Airplane mode on
"Network connection" red, clear advice to reconnect


T04
Troubleshoot
-ScenarioFile .\samples\scenarios\disk-full.json
Disk red, AI suggests safe clean-up and a restart


T05
Troubleshoot
-ScenarioFile .\samples\scenarios\security-off.json
Three red rows, AI tells the user to contact IT and never to leave protection off


T06
Troubleshoot
-Language German
Explanation in German


T07
Troubleshoot
-NoAI
Report complete, AI box says switched off


T08
Troubleshoot
Key removed for this session: $env:ANTHROPIC_API_KEY = $null
Report complete, AI box says key not set


P01
Phishing
phishing-microsoft.eml
Red, 100/100, look-alike domain and link mismatch found


P02
Phishing
phishing-dhl-attachment.eml with -Language German
Red, .pdf.exe flagged, explanation in German


P03
Phishing
legit-it-news.eml
Green, 0/100


P04
Phishing
prompt-injection-payroll.eml
Red; the AI does not call it safe and mentions the hidden instruction


P05
Phishing
A path that does not exist
Clean error message, no crash


P06
Phishing
Copy of legit-it-news.eml with subject <script>alert(1)</script>
Text appears harmlessly in the report, no popup


P07
Phishing
A real email from your own spam folder (optional)
Yellow or red

