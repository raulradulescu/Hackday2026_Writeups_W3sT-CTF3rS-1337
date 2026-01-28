# Anonymous Spotted Number - writeup

## Challenge
We are given an identifier: ASN 15238.
We must find which "product" appears most often in results associated with this ASN, then submit:
HACKDAY{topproductname}

## What we can use 
The screenshots show a Shodan view for an IP in ASN 15238 (66.17.185.1, Bill & Melinda Gates Foundation). In that view, Shodan includes a "TOP PRODUCTS" panel with product names and counts:

- ntpd: 9
- ciscoSystems: 4
- Microsoft IIS httpd: 3
- Cerberus FTP Server: 2
- nginx: 2

The question says the product is "more prevalent than others", so we select the product with the highest count.

## Steps
1. In Shodan, search for the ASN:
   - Use the Shodan search filter: asn:AS15238
2. Open the report/summary for that query (the UI shows a "View Report" style summary).
3. Locate the "TOP PRODUCTS" section.
4. Pick the top entry by count. In the screenshot, the highest count is "ntpd" with 9.

## Flag
HACKDAY{ntpd}
