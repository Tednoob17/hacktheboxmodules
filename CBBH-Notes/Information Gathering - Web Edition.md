

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
- ![[Pasted image 20241231182010.png]]


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

-