XSS vulnerabilities are solely executed on the client-side and hence do not directly affect the back-end server. They can only affect the user executing the vulnerability.
## Types of XSS

There are three main types of XSS vulnerabilities:

|Type|Description|
|---|---|
|`Stored (Persistent) XSS`|The most critical type of XSS, which occurs when user input is stored on the back-end database and then displayed upon retrieval (e.g., posts or comments)|
|`Reflected (Non-Persistent) XSS`|Occurs when user input is displayed on the page after being processed by the backend server, but without being stored (e.g., search result or error message)|
|`DOM-based XSS`|Another Non-Persistent XSS type that occurs when user input is directly shown in the browser and is completely processed on the client-side, without reaching the back-end server (e.g., through client-side HTTP parameters or anchor tags)|
## Stored XSS

The first and most critical type of XSS vulnerability is `Stored XSS` or `Persistent XSS`. If our injected XSS payload gets stored in the back-end database and retrieved upon visiting the page, this means that our XSS attack is persistent and may affect any user that visits the page.

## XSS Testing Payloads

![[Pasted image 20250111020149.png]]

#### Questions

Answer the question(s) below to complete this Section and earn cubes!

+ 2 To get the flag, use the same payload we used above, but change its JavaScript code to show the cookie instead of showing the url.
+ <script>alert(document.cookie)</script>
	`HTB{570r3d_f0r_3v3ry0n3_70_533}`
	![[Pasted image 20250111020235.png]]

## Reflected XSS
There are two types of `Non-Persistent XSS` vulnerabilities: `Reflected XSS`, which gets processed by the back-end server, and `DOM-based XSS`, which is completely processed on the client-side and never reaches the back-end server. Unlike Persistent XSS, `Non-Persistent XSS` vulnerabilities are temporary and are not persistent through page refreshes. Hence, our attacks only affect the targeted user and will not affect other users who visit the page.


![[Pasted image 20250111021440.png]]


In this case, we see that the error message now says `Task '' could not be added.`. Since our payload is wrapped with a `<script>` tag, it does not get rendered by the browser, so we get empty single quotes `''` instead. We can once again view the page source to confirm that the error message includes our XSS payload:

Code: html

```html
<div></div><ul class="list-unstyled" id="todo"><div style="padding-left:25px">Task '<script>alert(window.origin)</script>' could not be added.</div></ul>
```

As we can see, the single quotes indeed contain our XSS payload `'<script>alert(window.origin)</script>'`.

If we visit the `Reflected` page again, the error message no longer appears, and our XSS payload is not executed, which means that this XSS vulnerability is indeed `Non-Persistent`.

`But if the XSS vulnerability is Non-Persistent, how would we target victims with it?`
So, `to target a user, we can send them a URL containing our payload`. To get the URL, we can copy the URL from the URL bar in Firefox after sending our XSS payload, or we can right-click on the `GET` request in the `Network` tab and select `Copy>Copy URL`. Once the victim visits this URL, the XSS payload would execute:


![[Pasted image 20250111022242.png]]
#### Questions
Life Left: 87 minute(s)

+ 2 To get the flag, use the same payload we used above, but change its JavaScript code to show the cookie instead of showing the url.
	`HTB{r3fl3c73d_b4ck_2_m3}`
	![[Pasted image 20250111021232.png]]

![[Pasted image 20250111022420.png]]




## DOM XSS

The third and final type of XSS is another `Non-Persistent` type called `DOM-based XSS`. While `reflected XSS` sends the input data to the back-end server through HTTP requests, DOM XSS is completely processed on the client-side through JavaScript. DOM XSS occurs when JavaScript is used to change the page source through the `Document Object Model (DOM)`.

### Source & Sink


#### Questions

Answer the question(s) below to complete this Section and earn cubes!
+ 2 To get the flag, use the same payload we used above, but change its JavaScript code to show the cookie instead of showing the url.
	+ `HTB{pur3ly_cl13n7_51d3}` 
![[Pasted image 20250111030103.png]]
![[Pasted image 20250111030124.png]]



## XSS Discovery
#### Questions

Answer the question(s) below to complete this Section and earn cubes!

+ 2 Utilize some of the techniques mentioned in this section to identify the vulnerable input parameter found in the above server. What is the name of the vulnerable parameter?
	`email`
+ 2 What type of XSS was found on the above server? "name only"
	`Reflected`
	![[Pasted image 20250111174824.png]]

## Phishing
Another very common type of XSS attack is a phishing attack. Phishing attacks usually utilize legitimate-looking information to trick the victims into sending their sensitive information to the attacker. A common form of XSS phishing attacks is through injecting fake login forms that send the login details to the attacker's server, which may then be used to log in on behalf of the victim and gain control over their account and sensitive information.
`'> <script> alert('1') </script> <'` 



![[Pasted image 20250122002431.png]]


