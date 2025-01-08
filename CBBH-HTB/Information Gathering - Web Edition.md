

### Passive Reconnaissance

In contrast, passive reconnaissance involves gathering information about the target `without directly interacting` with it. This relies on analysing publicly available information and resources, such as: 

| Technique               | Description                                                                                                                     | Example                                                                                                                                           | Tools                                                                   | Risk of Detection                                                                                      |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `Search Engine Queries` | Utilising search engines to uncover information about the target, including websites, social media profiles, and news articles. | Searching Google for "`[Target Name] employees`" to find employee information or social media profiles.                                           | Google, DuckDuckGo, Bing, and specialised search engines (e.g., Shodan) | Very Low: Search engine queries are normal internet activity and unlikely to trigger alerts.           |
| `WHOIS Lookups`         | Querying WHOIS databases to retrieve domain registration details.                                                               | Performing a WHOIS lookup on a target domain to find the registrant's name, contact information, and name servers.                                | whois command-line tool, online WHOIS lookup services                   | Very Low: WHOIS queries are legitimate and do not raise suspicion.                                     |
| `DNS`                   | Analysing DNS records to identify subdomains, mail servers, and other infrastructure.                                           | Using `dig` to enumerate subdomains of a target domain.                                                                                           | dig, nslookup, host, dnsenum, fierce, dnsrecon                          | Very Low: DNS queries are essential for internet browsing and are not typically flagged as suspicious. |
| `Web Archive Analysis`  | Examining historical snapshots of the target's website to identify changes, vulnerabilities, or hidden information.             | Using the Wayback Machine to view past versions of a target website to see how it has changed over time.                                          | Wayback Machine                                                         | Very Low: Accessing archived versions of websites is a normal activity.                                |
| `Social Media Analysis` | Gathering information from social media platforms like LinkedIn, Twitter, or Facebook.                                          | Searching LinkedIn for employees of a target organisation to learn about their roles, responsibilities, and potential social engineering targets. | LinkedIn, Twitter, Facebook, specialised OSINT tools                    | Very Low: Accessing public social media profiles is not considered intrusive.                          |
| `Code Repositories`     | Analysing publicly accessible code repositories like GitHub for exposed credentials or vulnerabilities.                         | Searching GitHub for code snippets or repositories related to the target that might contain sensitive information or code vulnerabilities.        | GitHub, GitLab                                                          | Very Low: Code repositories are meant for public access, and searching them is not suspicious.         |


# WHOIS
![[Pasted image 20241231181805.png]]



- ![[Pasted image 20241231181840.png]]
- `292`
	![[Pasted image 20241231182010.png]]

	`admin@dnstinations.com` 
### Personal Research
#### Dork
### Google
- "index of" "parent directory" "sql.gz" "2024" <- On goole
	`.gz` : Parce que les admin aime bien le gunzip
	> Search : Dork for password reset , validation de compte 
	> Pro tips : Chercher les mots de passe md5 des clients que vous avez pentester pour regarder sur internet pour voir si les mdp sont deja connus
	> Puis faite une recherche google avec inurl: hash
	> Ou inurl: j_password inurl:j_username
	> 1064 mysql error ext:php inurl:search
	> "var/www" site:com
	> uncaught pdo __construct -denied -forum -forums
	> urlscan.io
	> 	page.url:pwd
	> publicwww.com <-  search engine of source code 
	> 	mysql_connect
	> 	localhost root depth :all3306
### Shodan

- html:"index of" html:"sql.gz" html:2024
- http.title:gitlab
- http.favicon.hash:1278323681 <- il y a un script open source qui permet de transformer n'importe quel image en favicon hash (il y a un alias sur lalubuntu)

- For student : shodan academic
### Censys
	https://search.censys.io
- labels = `open-dir` 

Petite ressource pour trouver des fchiers via directory listing : files.leakix.net
Extensions : dotgit, owasp penetration testing kit 
amalmuraii.me/posts/git-rce
pentesterkit.co.uk
crt.sh
rapiddns.io
pan.baidu.com inurl:pwd

### DNS
DNS servers store various resource records, each serving a specific purpose in the domain name resolution process. Let's explore some of the most common DNS concepts:
[a-z][]

| DNS Concept                 | Description                                                                      | Example                                                                                                                                 |
| --------------------------- | -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `Domain Name`               | A human-readable label for a website or other internet resource.                 | `www.example.com`                                                                                                                       |
| `IP Address`                | A unique numerical identifier assigned to each device connected to the internet. | `192.0.2.1`                                                                                                                             |
| `DNS Resolver`              | A server that translates domain names into IP addresses.                         | Your ISP's DNS server or public resolvers like Google DNS (`8.8.8.8`)                                                                   |
| `Root Name Server`          | The top-level servers in the DNS hierarchy.                                      | There are 13 root servers worldwide, named A-M: `a.root-servers.net`                                                                    |
| `TLD Name Server`           | Servers responsible for specific top-level domains (e.g., .com, .org).           | [Verisign](https://en.wikipedia.org/wiki/Verisign) for `.com`, [PIR](https://en.wikipedia.org/wiki/Public_Interest_Registry) for `.org` |
| `Authoritative Name Server` | The server that holds the actual IP address for a domain.                        | Often managed by hosting providers or domain registrars.                                                                                |
| `DNS Record Types`          | Different types of information stored in DNS.                                    | A, AAAA, CNAME, MX, NS, TXT, etc.                                                                                                       |

Now that we've explored the fundamental concepts of DNS, let's dive deeper into the building blocks of DNS information – the various record types. These records store different types of data associated with domain names, each serving a specific purpose:

| Record Type | Full Name                 | Description                                                                                                                                 | Zone File Example                                                                              |
| ----------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `A`         | Address Record            | Maps a hostname to its IPv4 address.                                                                                                        | `www.example.com.` IN A `192.0.2.1`                                                            |
| `AAAA`      | IPv6 Address Record       | Maps a hostname to its IPv6 address.                                                                                                        | `www.example.com.` IN AAAA `2001:db8:85a3::8a2e:370:7334`                                      |
| `CNAME`     | Canonical Name Record     | Creates an alias for a hostname, pointing it to another hostname.                                                                           | `blog.example.com.` IN CNAME `webserver.example.net.`                                          |
| `MX`        | Mail Exchange Record      | Specifies the mail server(s) responsible for handling email for the domain.                                                                 | `example.com.` IN MX 10 `mail.example.com.`                                                    |
| `NS`        | Name Server Record        | Delegates a DNS zone to a specific authoritative name server.                                                                               | `example.com.` IN NS `ns1.example.com.`                                                        |
| `TXT`       | Text Record               | Stores arbitrary text information, often used for domain verification or security policies.                                                 | `example.com.` IN TXT `"v=spf1 mx -all"` (SPF record)                                          |
| `SOA`       | Start of Authority Record | Specifies administrative information about a DNS zone, including the primary name server, responsible person's email, and other parameters. | `example.com.` IN SOA `ns1.example.com. admin.example.com. 2024060301 10800 3600 604800 86400` |
| `SRV`       | Service Record            | Defines the hostname and port number for specific services.                                                                                 | `_sip._udp.example.com.` IN SRV 10 5 5060 `sipserver.example.com.`                             |
| `PTR`       | Pointer Record            | Used for reverse DNS lookups, mapping an IP address to a hostname.                                                                          | `1.2.0.192.in-addr.arpa.` IN PTR `www.example.com.`                                            |
The "`IN`" in the examples stands for "Internet." It's a class field in DNS records that specifies the protocol family. In most cases, you'll see "`IN`" used, as it denotes the Internet protocol suite (IP) used for most domain names.
## Why DNS Matters for Web Recon

DNS is not merely a technical protocol for translating domain names; it's a critical component of a target's infrastructure that can be leveraged to uncover vulnerabilities and gain access during a penetration test:

- `Uncovering Assets`: DNS records can reveal a wealth of information, including subdomains, mail servers, and name server records. For instance, a `CNAME` record pointing to an outdated server (`dev.example.com` CNAME `oldserver.example.net`) could lead to a vulnerable system.
- `Mapping the Network Infrastructure`: You can create a comprehensive map of the target's network infrastructure by analysing DNS data. For example, identifying the name servers (`NS` records) for a domain can reveal the hosting provider used, while an `A` record for `loadbalancer.example.com` can pinpoint a load balancer. This helps you understand how different systems are connected, identify traffic flow, and pinpoint potential choke points or weaknesses that could be exploited during a penetration test.
- `Monitoring for Changes`: Continuously monitoring DNS records can reveal changes in the target's infrastructure over time. For example, the sudden appearance of a new subdomain (`vpn.example.com`) might indicate a new entry point into the network, while a `TXT` record containing a value like `_1password=...` strongly suggests the organization is using 1Password, which could be leveraged for social engineering attacks or targeted phishing campaigns.

- Which IP address maps to inlanefreight.com?
	- `134.209.24.248` 
	![[Pasted image 20250102125600.png]]
- Which domain is returned when querying the PTR record for 134.209.24.248?
- `inlanefreight.com`
	![[Pasted image 20250102130053.png]]
- What is the full domain returned when you query the mail records for facebook.com? 
- `smtpin.vvv.facebook.com`
	![[Pasted image 20250102130829.png]]

Surement une erreur ici

![[Pasted image 20250102130957.png]]

### Subdomain Bruteforcing
`Subdomain Brute-Force Enumeration` is a powerful active subdomain discovery technique that leverages pre-defined lists of potential subdomain names. This approach systematically tests these names against the target domain to identify valid subdomains. By using carefully crafted wordlists, you can significantly increase the efficiency and effectiveness of your subdomain discovery efforts.

There are several tools available that excel at brute-force enumeration:

| Tool                                                    | Description                                                                                                                     |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| [dnsenum](https://github.com/fwaeytens/dnsenum)         | Comprehensive DNS enumeration tool that supports dictionary and brute-force attacks for discovering subdomains.                 |
| [fierce](https://github.com/mschwager/fierce)           | User-friendly tool for recursive subdomain discovery, featuring wildcard detection and an easy-to-use interface.                |
| [dnsrecon](https://github.com/darkoperator/dnsrecon)    | Versatile tool that combines multiple DNS reconnaissance techniques and offers customisable output formats.                     |
| [amass](https://github.com/owasp-amass/amass)           | Actively maintained tool focused on subdomain discovery, known for its integration with other tools and extensive data sources. |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Simple yet effective tool for finding subdomains using various techniques, ideal for quick and lightweight scans.               |
| [puredns](https://github.com/d3mondev/puredns)          | Powerful and flexible DNS brute-forcing tool, capable of resolving and filtering results effectively.                           |

Let's see `dnsenum` in action by demonstrating how to enumerate subdomains for our target, `inlanefreight.com`. In this demonstration, we'll use the `subdomains-top1million-5000.txt` wordlist from [SecLists](https://github.com/danielmiessler/SecLists), which contains the top 5000 most common subdomains.

Code: bash

```bash
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r
```

In this command:

- `dnsenum --enum inlanefreight.com`: We specify the target domain we want to enumerate, along with a shortcut for some tuning options `--enum`.
- `-f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`: We indicate the path to the SecLists wordlist we'll use for brute-forcing. Adjust the path if your SecLists installation is different.
- `-r`: This option enables recursive subdomain brute-forcing, meaning that if `dnsenum` finds a subdomain, it will then try to enumerate subdomains of that subdomain.


- Using the known subdomains for inlanefreight.com (www, ns1, ns2, ns3, blog, support, customer), find any missing subdomains by brute-forcing possible domain names. Provide your answer with the complete subdomain, e.g., www.inlanefreight.com.
	`my.inlanefreight.com`
	![[Pasted image 20250102153523.png]]
![[Pasted image 20250102153538.png]]

# DNS Zone Transfers

Le transfert de zone DNS également connu de son opcode mnémotechnique _AXFR_, est un type de transaction DNS.


- After performing a zone transfer for the domain inlanefreight.htb on the target system, how many DNS records are retrieved from the target system's name server? Provide your answer as an integer, e.g, 123.
	`22`
![[Pasted image 20250102163759.png]]
- Within the zone record transferred above, find the ip address for ftp.admin.inlanefreight.htb. Respond only with the IP address, eg 127.0.0.1
	![[Pasted image 20250102165249.png]]
	`10.10.34.2`
- Within the same zone record, identify the largest IP address allocated within the 10.10.200 IP range. Respond with the full IP address, eg 10.10.200.1
	 `10.10.200.10`
	![[Pasted image 20250102165425.png]]


### Peu etre une erreur mais on garde voir ..


+++++

## Virtual Hosts

`virtual hosting` : is the ability of web servers to distinguish between multiple websites or applications sharing the same IP address.

The key difference between `VHosts` and `subdomains` is their relationship to the `Domain Name System (DNS)` and the web server's configuration.


## Virtual Host Discovery Tools

While manual analysis of `HTTP headers` and reverse `DNS lookups` can be effective, specialised `virtual host discovery tools` automate and streamline the process, making it more efficient and comprehensive. These tools employ various techniques to probe the target server and uncover potential `virtual hosts`.

Several tools are available to aid in the discovery of virtual hosts:

| Tool                                                 | Description                                                                                                      | Features                                                        |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| [gobuster](https://github.com/OJ/gobuster)           | A multi-purpose tool often used for directory/file brute-forcing, but also effective for virtual host discovery. | Fast, supports multiple HTTP methods, can use custom wordlists. |
| [Feroxbuster](https://github.com/epi052/feroxbuster) | Similar to Gobuster, but with a Rust-based implementation, known for its speed and flexibility.                  | Supports recursion, wildcard discovery, and various filters.    |
| [ffuf](https://github.com/ffuf/ffuf)                 | Another fast web fuzzer that can be used for virtual host discovery by fuzzing the `Host` header.                | Customizable wordlist input and filtering options.              |

### gobuster

Gobuster is a versatile tool commonly used for directory and file brute-forcing, but it also excels at virtual host discovery. It systematically sends HTTP requests with different `Host` headers to a target IP address and then analyses the responses to identify valid virtual hosts.

There are a couple of things you need to prepare to brute force `Host` headers:

1. `Target Identification`: First, identify the target web server's IP address. This can be done through DNS lookups or other reconnaissance techniques.
2. `Wordlist Preparation`: Prepare a wordlist containing potential virtual host names. You can use a pre-compiled wordlist, such as SecLists, or create a custom one based on your target's industry, naming conventions, or other relevant information.

The `gobuster` command to bruteforce vhosts generally looks like this:

Virtual Hosts

```shell-session
0ldka3n1x@htb[/htb]$ gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain
```

- The `-u` flag specifies the target URL (replace `<target_IP_address>` with the actual IP).
- The `-w` flag specifies the wordlist file (replace `<wordlist_file>` with the path to your wordlist).
- The `--append-domain` flag appends the base domain to each word in the wordlist.

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Target(s): Click here to spawn the target system!  

vHosts needed for these questions:

- `inlanefreight.htb`

+ 1 Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "web"? Answer using the full domain, e.g. "x.inlanefreight.htb"
	`web17611.inlanefreight.htb` 
+ 0 Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "vm"? Answer using the full domain, e.g. "x.inlanefreight.htb"
	`vm5.inlanefreight.htb`
+ 0 Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "br"? Answer using the full domain, e.g. "x.inlanefreight.htb"
	`browse.inlanefreight.htb` 
+ 0 Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "a"? Answer using the full domain, e.g. "x.inlanefreight.htb"
	`admin.inlanefreight.htb`
+ 0 Brute-force vhosts on the target system. What is the full subdomain that is prefixed with "su"? Answer using the full domain, e.g. "x.inlanefreight.htb"
	`support.inlanefreight.htb``

![[Pasted image 20250108173623.png]]

![[Pasted image 20250102202931.png]]


![[Pasted image 20250102204549.png]]
Continue it after

I case that you lost do : 

```bash
nano /etc/hosts
$IP_ADDR   $DNS
```

and continue your challenges
There are two popular options for searching CT logs:
### CT Logs and Web Recon




|Tool|Key Features|Use Cases|Pros|Cons|
|---|---|---|---|---|
|[crt.sh](https://crt.sh/)|User-friendly web interface, simple search by domain, displays certificate details, SAN entries.|Quick and easy searches, identifying subdomains, checking certificate issuance history.|Free, easy to use, no registration required.|Limited filtering and analysis options.|
|[Censys](https://search.censys.io/)|Powerful search engine for internet-connected devices, advanced filtering by domain, IP, certificate attributes.|In-depth analysis of certificates, identifying misconfigurations, finding related certificates and hosts.|Extensive data and filtering options, API access.|Requires registration (free tier available).|

### crt.sh lookup

While `crt.sh` offers a convenient web interface, you can also leverage its API for automated searches directly from your terminal. Let's see how to find all 'dev' subdomains on `facebook.com` using `curl` and `jq`:

Certificate Transparency Logs

```shell-session
0ldka3n1x@htb[/htb]$ curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[]
 | select(.name_value | contains("dev")) | .name_value' | sort -u
 
*.dev.facebook.com
*.newdev.facebook.com
*.secure.dev.facebook.com
dev.facebook.com
devvm1958.ftw3.facebook.com
facebook-amex-dev.facebook.com
facebook-amex-sign-enc-dev.facebook.com
newdev.facebook.com
secure.dev.facebook.com
```

- `curl -s "https://crt.sh/?q=facebook.com&output=json"`: This command fetches the JSON output from crt.sh for certificates matching the domain `facebook.com`.
- `jq -r '.[] | select(.name_value | contains("dev")) | .name_value'`: This part filters the JSON results, selecting only entries where the `name_value` field (which contains the domain or subdomain) includes the string "`dev`". The `-r` flag tells `jq` to output raw strings.
- `sort -u`: This sorts the results alphabetically and removes duplicates.




# Fingerprinting
### Banner Grabbing

Our first step is to gather information directly from the web server itself. We can do this using the `curl` command with the `-I` flag (or `--head`) to fetch only the HTTP headers, not the entire page content.

Fingerprinting

```shell-session
0ldka3n1x@htb[/htb]$ curl -I inlanefreight.com
```

The output will include the server banner, revealing the web server software and version number:

Fingerprinting

```shell-session
0ldka3n1x@htb[/htb]$ curl -I inlanefreight.com

HTTP/1.1 301 Moved Permanently
Date: Fri, 31 May 2024 12:07:44 GMT
Server: Apache/2.4.41 (Ubuntu)
Location: https://inlanefreight.com/
Content-Type: text/html; charset=iso-8859-1
```

In this case, we see that `inlanefreight.com` is running on `Apache/2.4.41`, specifically the `Ubuntu` version. This information is our first clue, hinting at the underlying technology stack. It's also trying to redirect to `https://inlanefreight.com/` so grab those banners too
![[Pasted image 20250102202729.png]]


### Wafw00f

`Web Application Firewalls` (`WAFs`) are security solutions designed to protect web applications from various attacks. Before proceeding with further fingerprinting, it's crucial to determine if `inlanefreight.com` employs a WAF, as it could interfere with our probes or potentially block our requests.

![[Pasted image 20250102203130.png]]



#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Target(s): Click here to spawn the target system!  

vHosts needed for these questions:

- `app.inlanefreight.local`
- `dev.inlanefreight.local`

+ 1 Determine the Apache version running on app.inlanefreight.local on the target system. (Format: 0.0.0)

	`2.4.41`
	![[Pasted image 20250102210225.png]]

+ 1 Which CMS is used on app.inlanefreight.local on the target system? Respond with the name only, e.g., WordPress.

	`joomla`

+ 1 On which operating system is the dev.inlanefreight.local webserver running in the target system? Respond with the name only, e.g., Debian.

	`Ubuntu`


![[Pasted image 20250102165528.png]]


![[Pasted image 20250103124406.png]]

![[Pasted image 20250103124544.png]]

Here also


![[Pasted image 20250103124440.png]]


# robots.txt

Technically, `robots.txt` is a simple text file placed in the root directory of a website (e.g., `www.example.com/robots.txt`). It adheres to the Robots Exclusion Standard, guidelines for how web crawlers should behave when visiting a website. This file contains instructions in the form of "directives" that tell bots which parts of the website they can and cannot crawl.

### Analyzing robots.txt

Here's an example of a robots.txt file:

Code: txt

```txt
User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/

User-agent: Googlebot
Crawl-delay: 10

Sitemap: https://www.example.com/sitemap.xml
```

This file contains the following directives:

- All user agents are disallowed from accessing the `/admin/` and `/private/` directories.
- All user agents are allowed to access the `/public/` directory.
- The `Googlebot` (Google's web crawler) is specifically instructed to wait 10 seconds between requests.
- The sitemap, located at `https://www.example.com/sitemap.xml`, is provided for easier crawling and indexing.

By analyzing this robots.txt, we can infer that the website likely has an admin panel located at `/admin/` and some private content in the `/private/` directory.




##  Creepy Crawlies
```bash
python3 ReconSpider.py http://inlanefreight.com
```

![[Pasted image 20250103201650.png]]

`inlanefreight-comp133.s3.amazonaws.htb`

![[Pasted image 20250103201513.png]]

## Search Engine Discovery


## Search Operators

Search operators are like search engines' secret codes. These special commands and modifiers unlock a new level of precision and control, allowing you to pinpoint specific types of information amidst the vastness of the indexed web.

While the exact syntax may vary slightly between search engines, the underlying principles remain consistent. Let's delve into some essential and advanced search operators:

|Operator|Operator Description|Example|Example Description|
|:--|:--|:--|:--|
|`site:`|Limits results to a specific website or domain.|`site:example.com`|Find all publicly accessible pages on example.com.|
|`inurl:`|Finds pages with a specific term in the URL.|`inurl:login`|Search for login pages on any website.|
|`filetype:`|Searches for files of a particular type.|`filetype:pdf`|Find downloadable PDF documents.|
|`intitle:`|Finds pages with a specific term in the title.|`intitle:"confidential report"`|Look for documents titled "confidential report" or similar variations.|
|`intext:` or `inbody:`|Searches for a term within the body text of pages.|`intext:"password reset"`|Identify webpages containing the term “password reset”.|
|`cache:`|Displays the cached version of a webpage (if available).|`cache:example.com`|View the cached version of example.com to see its previous content.|
|`link:`|Finds pages that link to a specific webpage.|`link:example.com`|Identify websites linking to example.com.|
|`related:`|Finds websites related to a specific webpage.|`related:example.com`|Discover websites similar to example.com.|
|`info:`|Provides a summary of information about a webpage.|`info:example.com`|Get basic details about example.com, such as its title and description.|
|`define:`|Provides definitions of a word or phrase.|`define:phishing`|Get a definition of "phishing" from various sources.|
|`numrange:`|Searches for numbers within a specific range.|`site:example.com numrange:1000-2000`|Find pages on example.com containing numbers between 1000 and 2000.|
|`allintext:`|Finds pages containing all specified words in the body text.|`allintext:admin password reset`|Search for pages containing both "admin" and "password reset" in the body text.|
|`allinurl:`|Finds pages containing all specified words in the URL.|`allinurl:admin panel`|Look for pages with "admin" and "panel" in the URL.|
|`allintitle:`|Finds pages containing all specified words in the title.|`allintitle:confidential report 2023`|Search for pages with "confidential," "report," and "2023" in the title.|
|`AND`|Narrows results by requiring all terms to be present.|`site:example.com AND (inurl:admin OR inurl:login)`|Find admin or login pages specifically on example.com.|
|`OR`|Broadens results by including pages with any of the terms.|`"linux" OR "ubuntu" OR "debian"`|Search for webpages mentioning Linux, Ubuntu, or Debian.|
|`NOT`|Excludes results containing the specified term.|`site:bank.com NOT inurl:login`|Find pages on bank.com excluding login pages.|
|`*` (wildcard)|Represents any character or word.|`site:socialnetwork.com filetype:pdf user* manual`|Search for user manuals (user guide, user handbook) in PDF format on socialnetwork.com.|
|`..` (range search)|Finds results within a specified numerical range.|`site:ecommerce.com "price" 100..500`|Look for products priced between 100 and 500 on an e-commerce website.|
|`" "` (quotation marks)|Searches for exact phrases.|`"information security policy"`|Find documents mentioning the exact phrase "information security policy".|
|`-` (minus sign)|Excludes terms from the search results.|`site:news.com -inurl:sports`|Search for news articles on news.com excluding sports-related content.|
- https://www.exploit-db.com/google-hacking-database
- 
## Web Archives


#### Questions

Answer the question(s) below to complete this Section and earn cubes!

+  How many Pen Testing Labs did HackTheBox have on the 8th August 2018? Answer with an integer, eg 1234.
	`74`
	![[Pasted image 20250103221323.png]]
+  How many members did HackTheBox have on the 10th June 2017? Answer with an integer, eg 1234.
	 `3054`
	 ![[Pasted image 20250103221050.png]]
	 
+ 0 Going back to March 2002, what website did the facebook.com domain redirect too? Answer with the full domain, eg http://www.facebook.com/
+ `http://site.aboutface.com/` 
	![[Pasted image 20250103221546.png]]
	
+  According to the paypal.com website in October 1999, what could you use to "beam money to anyone"? Answer with the product name, eg My Device, remove the ™ from your answer.
	`Palm™ 0rganizer.` -> `Palm 0rganizer.`
	![[Pasted image 20250103222057.png]]
	
+  Going back to November 1998 on google.com, what address hosted the non-alpha "Google Search Engine Prototype" of Google? Answer with the full address, eg http://google.com
	`http://google.stanford.edu/` 
	![[Pasted image 20250103222627.png]]
	![[Pasted image 20250103222540.png]]
	
+ 0 Going back to March 2000 on www.iana.org, when exacty was the site last updated? Answer with the date in the footer, eg 11-March-99
	`29-May-2000` 
	![[Pasted image 20250103225002.png]]

+ 0 According to the wikipedia.com snapshot taken in March 2001, how many pages did they have over? Answer with the number they state without any commas, eg 2000 not 2,000
	`13000`
	![[Pasted image 20250103225321.png]]




## Automating Recon


## Skills Assessment
vHosts needed for these questions:

- `inlanefreight.htb`

+ 1 What is the IANA ID of the registrar of the inlanefreight.com domain?
	`468`
	![[Pasted image 20250105194115.png]]
+ 1 What http server software is powering the inlanefreight.htb site on the target system? Respond with the name of the software, not the version, e.g., Apache.
	`nginx`
		![[Pasted image 20250105194321.png]]
+ 1 What is the API key in the hidden admin directory that you have discovered on the target system?
	
+ 4 After crawling the inlanefreight.htb domain on the target system, what is the email address you have found? Respond with the full email, e.g., mail@inlanefreight.htb.
	
+ 1 What is the API key the inlanefreight.htb developers will be changing too?
	



# END

