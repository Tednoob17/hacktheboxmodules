Testing web requests to back-end servers make up the bulk of Web Application Penetration Testing, which includes concepts that apply to both web and mobile applications. To capture the requests and traffic passing between applications and back-end servers and manipulate these types of requests for testing purposes, we need to use `Web Proxies`.

Web proxies are specialized tools that can be set up between a browser/mobile application and a back-end server to capture and view all the web requests being sent between both ends, essentially acting as man-in-the-middle (MITM) tools. While other `Network Sniffing` applications, like Wireshark, operate by analyzing all local traffic to see what is passing through a network, Web Proxies mainly work with web ports such as, but not limited to, `HTTP/80` and `HTTPS/443`.
While the primary use of web proxies is to capture and replay HTTP requests, they have many other features that enable different uses for web proxies.



![[Pasted image 20241228002022.png]]

`HTB{1n73rc3p73d_1n_7h3_m1ddl3}`

![[Pasted image 20241228162232.png]]

![[Pasted image 20241228162306.png]]

`HTB{qu1ckly_r3p3471n6_r3qu3575}`

![[Pasted image 20241228165330.png]]

![[Pasted image 20241228165535.png]]

![[Pasted image 20241228165557.png]]

`HTB{3nc0d1n6_n1nj4}`


## Proxychains
One very useful tool in Linux is [proxychains](https://github.com/haad/proxychains), which routes all traffic coming from any command-line tool to any proxy we specify. `Proxychains` adds a proxy to any command-line tool and is hence the simplest and easiest method to route web traffic of command-line tools through our web proxies.

To use `proxychains`, we first have to edit `/etc/proxychains.conf`, comment out the final line and add the following line at the end of it:
![[Pasted image 20241228170631.png]]

![[Pasted image 20241228170838.png]]

Quiet mode (Line 49)

![[Pasted image 20241228171408.png]]


Now testing with another website 
![[Pasted image 20241228203812.png]]


![[Pasted image 20241228203838.png]]
### Skip verification

Tell curl to _not_ verify the peer with `-k`/`--insecure`.

We **strongly** recommend this is avoided and that even if you end up doing this for experimentation or development, **never** skip verification in production.


![[Pasted image 20241228204139.png]]
It's can be disable the request sended work fine.

## Nmap

![[Pasted image 20241228172308.png]]

`-Pn` flag to skip host discovery (as recommended on the man page).

`-sC` flag to examine what an nmap script scan does

```
Note: Nmap's built-in proxy is still in its experimental phase, as mentioned by its manual (`man nmap`), so not all functions or traffic may be routed through the proxy. In these cases, we can simply resort to `proxychains`, as we did earlier.
```

## Intruder



![[Pasted image 20241230014336.png]]

![[Pasted image 20241230014416.png]]

`HTB{burp_1n7rud3r_fuzz3r!}`

## ZAP Fuzzer
I don't user ZAP so we can use hand : 
![[Pasted image 20241230033738.png]]

```bash
while read -r line; do
  echo -n "$line" | md5sum
done < `fzf-wordlists` > hashed_wordlists.txt
```


![[Pasted image 20241230033826.png]]

![[Pasted image 20241230033754.png]]

The user is `user` 

![[Pasted image 20241230034456.png]]

`HTB{fuzz1n6_my_f1r57_c00k13}`


# Skills Assessment - Using Web Proxies
- 1 

![[Pasted image 20241230212241.png]]

`HTB{d154bl3d_bu770n5_w0n7_570p_m3}`



- 2 
To Cookie strings to -> ASCII Hex to -> base64 to strings required for answers (try to decode the cookie until you get a value with 31-characters.)
![[Pasted image 20241230182137.png]]

```ex

4d325268597a6b7a596a686a5a4449314d4746684f474d7859544d325a6d5a6d597a63355954453359513d3d <- 

M2RhYzkzYjhjZDI1MGFhOGMxYTM2ZmZmYzc5YTE3YQ==

3dac93b8cd250aa8c1a36fffc79a17a
```

`3dac93b8cd250aa8c1a36fffc79a17a`

```bash
echo  -n "3dac93b8cd250aa8c1a36fffc79a17a"|base64|hex
```


- 3


```bash
while read -r char; do
  echo  "3dac93b8cd250aa8c1a36fffc79a17a$char"  
done < `fzf-wordlists` > perso_hash.txt
```

```
3dac93b8cd250aa8c1a36fffc79a17a0
3dac93b8cd250aa8c1a36fffc79a17a1
3dac93b8cd250aa8c1a36fffc79a17a2
3dac93b8cd250aa8c1a36fffc79a17a3
3dac93b8cd250aa8c1a36fffc79a17a4
3dac93b8cd250aa8c1a36fffc79a17a5
3dac93b8cd250aa8c1a36fffc79a17a6
3dac93b8cd250aa8c1a36fffc79a17a7
3dac93b8cd250aa8c1a36fffc79a17a8
3dac93b8cd250aa8c1a36fffc79a17a9
3dac93b8cd250aa8c1a36fffc79a17aa
3dac93b8cd250aa8c1a36fffc79a17ab
3dac93b8cd250aa8c1a36fffc79a17ac
3dac93b8cd250aa8c1a36fffc79a17ad
3dac93b8cd250aa8c1a36fffc79a17ae
3dac93b8cd250aa8c1a36fffc79a17af
3dac93b8cd250aa8c1a36fffc79a17ag
3dac93b8cd250aa8c1a36fffc79a17ah
3dac93b8cd250aa8c1a36fffc79a17ai
3dac93b8cd250aa8c1a36fffc79a17aj
3dac93b8cd250aa8c1a36fffc79a17ak
3dac93b8cd250aa8c1a36fffc79a17al
3dac93b8cd250aa8c1a36fffc79a17am
3dac93b8cd250aa8c1a36fffc79a17an
3dac93b8cd250aa8c1a36fffc79a17ao
3dac93b8cd250aa8c1a36fffc79a17ap
3dac93b8cd250aa8c1a36fffc79a17aq
3dac93b8cd250aa8c1a36fffc79a17ar
3dac93b8cd250aa8c1a36fffc79a17as
3dac93b8cd250aa8c1a36fffc79a17at
3dac93b8cd250aa8c1a36fffc79a17au
3dac93b8cd250aa8c1a36fffc79a17av
3dac93b8cd250aa8c1a36fffc79a17aw
3dac93b8cd250aa8c1a36fffc79a17ax
3dac93b8cd250aa8c1a36fffc79a17ay
3dac93b8cd250aa8c1a36fffc79a17az
3dac93b8cd250aa8c1a36fffc79a17aA
3dac93b8cd250aa8c1a36fffc79a17aB
3dac93b8cd250aa8c1a36fffc79a17aC
3dac93b8cd250aa8c1a36fffc79a17aD
3dac93b8cd250aa8c1a36fffc79a17aE
3dac93b8cd250aa8c1a36fffc79a17aF
3dac93b8cd250aa8c1a36fffc79a17aG
3dac93b8cd250aa8c1a36fffc79a17aH
3dac93b8cd250aa8c1a36fffc79a17aI
3dac93b8cd250aa8c1a36fffc79a17aJ
3dac93b8cd250aa8c1a36fffc79a17aK
3dac93b8cd250aa8c1a36fffc79a17aL
3dac93b8cd250aa8c1a36fffc79a17aM
3dac93b8cd250aa8c1a36fffc79a17aN
3dac93b8cd250aa8c1a36fffc79a17aO
3dac93b8cd250aa8c1a36fffc79a17aP
3dac93b8cd250aa8c1a36fffc79a17aQ
3dac93b8cd250aa8c1a36fffc79a17aR
3dac93b8cd250aa8c1a36fffc79a17aS
3dac93b8cd250aa8c1a36fffc79a17aT
3dac93b8cd250aa8c1a36fffc79a17aU
3dac93b8cd250aa8c1a36fffc79a17aV
3dac93b8cd250aa8c1a36fffc79a17aW
3dac93b8cd250aa8c1a36fffc79a17aX
3dac93b8cd250aa8c1a36fffc79a17aY
3dac93b8cd250aa8c1a36fffc79a17aZ
```


![[Pasted image 20241230215505.png]]

`4d325268597a6b7a596a686a5a4449314d4746684f474d7859544d325a6d5a6d597a6335595445335958593d`

![[Pasted image 20241230215549.png]]

`HTB{burp_1n7rud3r_n1nj4!}`

- 4
![[Pasted image 20241230220159.png]]


![[Pasted image 20241230220244.png]]


`CFIDE`

![[Pasted image 20241230220323.png]]

