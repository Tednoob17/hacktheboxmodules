
# Web Fuzzing
The term `fuzzing` refers to a testing technique that sends various types of user input to a certain interface to study how it would react. If we were fuzzing for SQL injection vulnerabilities, we would be sending random special characters and seeing how the server would react. If we were fuzzing for a buffer overflow, we would be sending long strings and incrementing their length to see if and when the binary would break.

#### Questions

Answer the question(s) below to complete this Section and earn cubes!


+ 0 In addition to the directory we found above, there is another directory that can be found. What is it?
	`forum`
	![[Pasted image 20250106144414.png]]
	![[Pasted image 20250106144438.png]]
	The only 301 code that we found


## Page Fuzzing

#### Questions

Answer the question(s) below to complete this Section and earn cubes!


+ 1 Try to use what you learned in this section to fuzz the '/blog' directory and find all pages. One of them should contain a flag. What is the flag?
	+ `HTB{bru73_f0r_c0mm0n_p455w0rd5}`
![[Pasted image 20250106153350.png]]
![[Pasted image 20250106153412.png]]


## Recursive Fuzzing
#### Questions

Answer the question(s) below to complete this Section and earn cubes!
+ Try to repeat what you learned so far to find more files/directories. One of them should give you a flag. What is the content of the flag?
	`HTB{fuzz1n6_7h3_w3b!}`

```bash
 ffuf -u http://academy.htb:36960/FUZZ -w `fzf-wordlists` -recursion -recursion-depth 1  -e .php -v
```

![[Pasted image 20250108013944.png]]
![[Pasted image 20250108014054.png]]

![[Pasted image 20250108014240.png]]

## Sub-domain Fuzzing

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

+ 0 Try running a sub-domain fuzzing test on 'inlanefreight.com' to find a customer sub-domain portal. What is the full domain of it?
	+ `customer.inlanefreight.com` 
	![[Pasted image 20250106201056.png]]

## Vhost Fuzzing

The key difference between VHosts and sub-domains is that a VHost is basically a 'sub-domain' served on the same server and has the same IP, such that a single IP could be serving two or more different websites.
`VHosts may or may not have public DNS records.`

In many cases, many websites would actually have sub-domains that are not public and will not publish them in public DNS records, and hence if we visit them in a browser, we would fail to connect, as the public DNS would not know their IP. Once again, if we use the `sub-domain fuzzing`, we would only be able to identify public sub-domains but will not identify any sub-domains that are not public.

This is where we utilize `VHosts Fuzzing` on an IP we already have. We will run a scan and test for scans on the same IP, and then we will be able to identify both public and non-public sub-domains and VHosts.

To scan for VHosts, without manually adding the entire wordlist to our `/etc/hosts`, we will be fuzzing HTTP headers, specifically the `Host:` header. To do that, we can use the `-H` flag to specify a header and will use the `FUZZ` keyword within it, as follows:

```bash
ka3n7x@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'
```


We see that all words in the wordlist are returning `200 OK`! This is expected, as we are simply changing the header while visiting `http://academy.htb:PORT/`. So, we know that we will always get `200 OK`. However, if the VHost does exist and we send a correct one in the header, we should get a different response size, as in that case, we would be getting the page from that VHosts, which is likely to show a different page.

------------------------------------------------------
Nous voyons que tous les mots de la liste de mots renvoient « 200 OK » ! C'est normal, car nous modifions simplement l'en-tête lors de la visite de « http://academy.htb:PORT/ ». Nous savons donc que nous obtiendrons toujours « 200 OK ». Cependant, si le VHost existe et que nous envoyons un correct dans l'en-tête, nous devrions obtenir une taille de réponse différente, car dans ce cas, nous obtiendrions la page de ce VHost, qui affichera probablement une page différente.


##  Filtering Results


```shell-session
ka3n7x@htb[/htb]$ ffuf -h
...SNIP...
MATCHER OPTIONS:
  -mc              Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403)
  -ml              Match amount of lines in response
  -mr              Match regexp
  -ms              Match HTTP response size
  -mw              Match amount of words in response

FILTER OPTIONS:
  -fc              Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl              Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fr              Filter regexp
  -fs              Filter HTTP response size. Comma separated list of sizes and ranges
  -fw              Filter by amount of words in response. Comma separated list of word counts and ranges
<...SNIP...>
```

Dans ce cas, nous ne pouvons pas utiliser la correspondance, car nous ne savons pas quelle serait la taille de la réponse des autres VHosts. Nous connaissons la taille de la réponse des résultats incorrects, qui, comme le montre le test ci-dessus, est de` 900`, et nous pouvons la filtrer avec `-fs 900`. Maintenant, répétons la même commande précédente, ajoutons l'indicateur ci-dessus et voyons ce que nous obtenons :

![[Pasted image 20250106204605.png]]

Note 1: Don't forget to add "admin.academy.htb" to "/etc/hosts".

Note 2: If your exercise has been restarted, ensure you still have the correct port when visiting the website.

We see that we can access the page, but we get an empty page, unlike what we got with `academy.htb`, therefore confirming this is indeed a different VHost. We can even visit `https://admin.academy.htb:PORT/blog/index.php`, and we will see that we would get a `404 PAGE NOT FOUND`, confirming that we are now indeed on a different VHost.

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

+ 0 Try running a VHost fuzzing scan on 'academy.htb', and see what other VHosts you get. What other VHosts did you get?
	`test.academy.htb` 
![[Pasted image 20250108021301.png]]
I also found : `admin.academy.htb` 
![[Pasted image 20250108021339.png]]

## Parameter Fuzzing - GET

+ 0 Using what you learned in this section, run a parameter fuzzing scan on this page. what is the parameter accepted by this webpage?
	`user`
	
![[Pasted image 20250108031602.png]]

![[Pasted image 20250108031720.png]]

## Parameter Fuzzing - POST
To fuzz the `data` field with `ffuf`, we can use the `-d` flag, as we saw previously in the output of `ffuf -h`. We also have to add `-X POST` to send `POST` requests.

Tip: In PHP, "POST" data "content-type" can only accept "application/x-www-form-urlencoded". So, we can set that in "ffuf" with "-H 'Content-Type: application/x-www-form-urlencoded'".

So, let us repeat what we did earlier, but place our `FUZZ` keyword after the `-d` flag:


![[Pasted image 20250108032459.png]]

As we can see this time, we got a couple of hits, the same one we got when fuzzing `GET` and another parameter, which is `id`. Let's see what we get if we send a `POST` request with the `id` parameter. We can do that with `curl`, as follows:

Parameter Fuzzing - POST

```shell-session
ka3n7x@htb[/htb]$ curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'

<div class='center'><p>Invalid id!</p></div>
<...SNIP...>
```

As we can see, the message now says `Invalid id!`.

## Value Fuzzing
#### Questions

Answer the question(s) below to complete this Section and earn cubes!

+ 1 Try to create the 'ids.txt' wordlist, identify the accepted value with a fuzzing scan, and then use it in a 'POST' request with 'curl' to collect the flag. What is the content of the flag?
	`HTB{p4r4m373r_fuzz1n6_15_k3y!}`
	![[Pasted image 20250108033302.png]]
	![[Pasted image 20250108033318.png]]
	![[Pasted image 20250108033429.png]]


# Skills Assessment - Web Fuzzing
#### Questions

Answer the question(s) below to complete this Section and earn cubes!

Target(s): 83.136.250.212:55640

  

Life Left: 34 minute(s)

+ 1 Run a sub-domain/vhost fuzzing scan on '*.academy.htb' for the IP shown above. What are all the sub-domains you can identify? (Only write the sub-domain name)
	`archive test faculty` 
	![[Pasted image 20250108043117.png]]
+ 1 Before you run your page fuzzing scan, you should first run an extension fuzzing scan. What are the different extensions accepted by the domains?
	`php phps` , ` php7` ?
	![[Pasted image 20250108044313.png]]
+ 2 One of the pages you will identify should say 'You don't have access!'. What is the full page URL?
	
+ 1 In the page from the previous question, you should be able to find multiple parameters that are accepted by the page. What are they?
	
+ 2 Try fuzzing the parameters you identified for working values. One of them should return a flag. What is the content of the flag?
	

 
# Cheatsheet

# Ffuf

|**Command**|**Description**|
|---|---|
|`ffuf -h`|ffuf help|
|`ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ`|Directory Fuzzing|
|`ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ`|Extension Fuzzing|
|`ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php`|Page Fuzzing|
|`ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v`|Recursive Fuzzing|
|`ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/`|Sub-domain Fuzzing|
|`ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx`|VHost Fuzzing|
|`ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx`|Parameter Fuzzing - GET|
|`ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`|Parameter Fuzzing - POST|
|`ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`|Value Fuzzing|

# Wordlists

|**Command**|**Description**|
|---|---|
|`/opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt`|Directory/Page Wordlist|
|`/opt/useful/seclists/Discovery/Web-Content/web-extensions.txt`|Extensions Wordlist|
|`/opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt`|Domain Wordlist|
|`/opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt`|Parameters Wordlist|

# Misc

|**Command**|**Description**|
|---|---|
|`sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'`|Add DNS entry|
|`for i in $(seq 1 1000); do echo $i >> ids.txt; done`|Create Sequence Wordlist|
|`curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'`|curl w/ POST|
