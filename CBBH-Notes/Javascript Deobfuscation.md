#### Questions

+ 1 Repeat what you learned in this section, and you should find a secret flag, what is it?
+ `HTB{4lw4y5_r34d_7h3_50urc3}`
![[Pasted image 20250109035425.png]]

## Code Obfuscation
#### What is obfuscation

Obfuscation is a technique used to make a script more difficult to read by humans but allows it to function the same from a technical point of view, though performance may be slower. This is usually achieved automatically by using an obfuscation tool, which takes code as an input, and attempts to re-write the code in a way that is much more difficult to read, depending on its design.

`It must be noted that doing authentication or encryption on the client-side is not recommended, as code is more prone to attacks this way.`

The most common usage of obfuscation, however, is for malicious actions. It is common for attackers and malicious actors to obfuscate their malicious scripts to prevent Intrusion Detection and Prevention systems from detecting their scripts. In the next section, we will learn how to obfuscate a simple JavaScript code and attempt running it before and after obfuscation to note any differences.

### Basic Obfuscation

##### Minifying JavaScript code
A common way of reducing the readability of a snippet of JavaScript code while keeping it fully functional is JavaScript minification. `Code minification` means having the entire code in a single (often very long) line. `Code minification` is more useful for longer code, as if our code only consisted of a single line, it would not look much different when minified.
Many tools can help us minify JavaScript code, like [javascript-minifier](https://javascript-minifier.com/).
Usually, minified JavaScript code is saved with the extension `.min.js`.

Note: Code minification is not exclusive to JavaScript, and can be applied to many other languages, as can be seen on [javascript-minifier](https://javascript-minifier.com/).

#### Packing JavaScript code
Now, let us obfuscate our line of code to make it more obscure and difficult to read. First, we will try [BeautifyTools](http://beautifytools.com/javascript-obfuscator.php) to obfuscate our code:

```javascript
eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('5.4(\'3 2 1 0\');',6,6,'Module|Deobfuscation|JavaScript|HTB|log|console'.split('|'),0,{}))
```

We see that our code became much more obfuscated and difficult to read. We can copy this code into [https://jsconsole.com](https://jsconsole.com), to verify that it still does its main function:
![[Pasted image 20250109040720.png]]

Note: The above type of obfuscation is known as "packing", which is usually recognizable from the six function arguments used in the initial function "function(p,a,c,k,e,d)".

A `packer` obfuscation tool usually attempts to convert all words and symbols of the code into a list or a dictionary and then refer to them using the `(p,a,c,k,e,d)` function to re-build the original code during execution. The `(p,a,c,k,e,d)` can be different from one packer to another. However, it usually contains a certain order in which the words and symbols of the original code were packed to know how to order them during execution.

While a packer does a great job reducing the code's readability, we can still see its main strings written in cleartext, which may reveal some of its functionality. This is why we may want to look for better ways to obfuscate our code.


## Advanced Obfuscation
So far, we have been able to make our code obfuscated and more difficult to read. However, the code still contains strings in cleartext, which may reveal its original functionality. In this section, we will try a couple of tools that should completely obfuscate the code and hide any remnants of its original functionality.

#### Obfuscator
Let's visit [https://obfuscator.io](https://obfuscator.io). Before we click `obfuscate`, we will change `String Array Encoding` to `Base64`, as seen below:

![[Pasted image 20250109041325.png]]

We get the following code:

Code: javascript

```javascript
var _0x1ec6=['Bg9N','sfrciePHDMfty3jPChqGrgvVyMz1C2nHDgLVBIbnB2r1Bgu='];(function(_0x13249d,_0x1ec6e5){var _0x14f83b=function(_0x3f720f){while(--_0x3f720f){_0x13249d['push'](_0x13249d['shift']());}};_0x14f83b(++_0x1ec6e5);}(_0x1ec6,0xb4));var _0x14f8=function(_0x13249d,_0x1ec6e5){_0x13249d=_0x13249d-0x0;var _0x14f83b=_0x1ec6[_0x13249d];if(_0x14f8['eOTqeL']===undefined){var _0x3f720f=function(_0x32fbfd){var _0x523045='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=',_0x4f8a49=String(_0x32fbfd)['replace'](/=+$/,'');var _0x1171d4='';for(var _0x44920a=0x0,_0x2a30c5,_0x443b2f,_0xcdf142=0x0;_0x443b2f=_0x4f8a49['charAt'](_0xcdf142++);~_0x443b2f&&(_0x2a30c5=_0x44920a%0x4?_0x2a30c5*0x40+_0x443b2f:_0x443b2f,_0x44920a++%0x4)?_0x1171d4+=String['fromCharCode'](0xff&_0x2a30c5>>(-0x2*_0x44920a&0x6)):0x0){_0x443b2f=_0x523045['indexOf'](_0x443b2f);}return _0x1171d4;};_0x14f8['oZlYBE']=function(_0x8f2071){var _0x49af5e=_0x3f720f(_0x8f2071);var _0x52e65f=[];for(var _0x1ed1cf=0x0,_0x79942e=_0x49af5e['length'];_0x1ed1cf<_0x79942e;_0x1ed1cf++){_0x52e65f+='%'+('00'+_0x49af5e['charCodeAt'](_0x1ed1cf)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(_0x52e65f);},_0x14f8['qHtbNC']={},_0x14f8['eOTqeL']=!![];}var _0x20247c=_0x14f8['qHtbNC'][_0x13249d];return _0x20247c===undefined?(_0x14f83b=_0x14f8['oZlYBE'](_0x14f83b),_0x14f8['qHtbNC'][_0x13249d]=_0x14f83b):_0x14f83b=_0x20247c,_0x14f83b;};console[_0x14f8('0x0')](_0x14f8('0x1'));
```

This code is obviously more obfuscated, and we can't see any remnants of our original code. We can now try running it in [https://jsconsole.com](https://jsconsole.com) to verify that it still performs its original function. Try playing with the obfuscation settings in [https://obfuscator.io](https://obfuscator.io) to generate even more obfuscated code, and then try rerunning it in [https://jsconsole.com](https://jsconsole.com) to verify it still performs its original function.

#### More Obfuscation

Now we should have a clear idea of how code obfuscation works. There are still many variations of code obfuscation tools, each of which obfuscates the code differently. Take the following JavaScript code, for example:

Code: javascript

```javascript
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(!
...SNIP...
[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]](!+[]+!+[]+[+[]])))()
```

We can still run this code, and it would still perform its original function:
![[Pasted image 20250109041514.png]]
'We can try obfuscating code using the same tool in [JSF](http://www.jsfuck.com), and then rerunning it. We will notice that the code may take some time to run, which shows how code obfuscation could affect the performance, as previously mentioned.

There are many other JavaScript obfuscators, like [JJ Encode](https://utf-8.jp/public/jjencode.html) or [AA Encode](https://utf-8.jp/public/aaencode.html). However, such obfuscators usually make code execution/compilation very slow, so it is not recommended to be used unless for an obvious reason, like bypassing web filters or restrictions.

## Deobfuscation


### Beautify
We see that the current code we have is all written in a single line. This is known as `Minified JavaScript` code. In order to properly format the code, we need to `Beautify` our code. The most basic method for doing so is through our `Browser Dev Tools`.

Furthermore, we can utilize many online tools or code editor plugins, like [Prettier](https://prettier.io/playground/) or [Beautifier](https://beautifier.io/). 


#### Deobfuscate

We can find many good online tools to deobfuscate JavaScript code and turn it into something we can understand. One good tool is [UnPacker](https://matthewfl.com/unPacker.html). Let's try copying our above-obfuscated code and run it in UnPacker by clicking the `UnPack` button.

Tip: Ensure you do not leave any empty lines before the script, as it may affect the deobfuscation process and give inaccurate results.

As previously mentioned, the above-used method of obfuscation is `packing`. Another way of `unpacking` such code is to find the `return` value at the end and use `console.log` to print it instead of executing it.

#### Questions

+ 1 Using what you learned in this section, try to deobfuscate 'secret.js' in order to get the content of the flag. What is the flag?
	`HTB{1_4m_7h3_53r14l_g3n3r470r!}` 
	Prettier
![[Pasted image 20250109043844.png]]

Unpacker 
![[Pasted image 20250109043947.png]]

## Code Analysis

```js
function generateSerial()
	{
	var flag="HTB
		{
		1_4m_7h3_53r14l_g3n3r470r!
	}
	";
	var xhr=new XMLHttpRequest();
	var url="/serial.php";
	xhr.open("POST",url,true);
	xhr.send(null)
}
```


## HTTP Requests

#### Questions
Life Left: 36 minute(s)

+ 1 Try applying what you learned in this section by sending a 'POST' request to '/serial.php'. What is the response you get?
	`N2gxNV8xNV9hX3MzY3IzN19tMzU1NGcz`
	![[Pasted image 20250109044830.png]]

## Decoding
#### Base64 Encode

To encode any text into `base64` in Linux, we can echo it and pipe it with '`|`' to `base64`:

Decoding

```shell-session
ka3n7x@htb[/htb]$ echo https://www.hackthebox.eu/ | base64

aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K
```

#### Base64 Decode

If we want to decode any `base64` encoded string, we can use `base64 -d`, as follows:

Decoding

```shell-session
ka3n7x@htb[/htb]$ echo aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K | base64 -d

https://www.hackthebox.eu/
```

---

## Hex

Another common encoding method is `hex` encoding, which encodes each character into its `hex` order in the `ASCII` table. For example, `a` is `61` in hex, `b` is `62`, `c` is `63`, and so on. You can find the full `ASCII` table in Linux using the `man ascii` command.

#### Spotting Hex

Any string encoded in `hex` would be comprised of hex characters only, which are 16 characters only: 0-9 and a-f. That makes spotting `hex` encoded strings just as easy as spotting `base64` encoded strings.

#### Hex Encode

To encode any string into `hex` in Linux, we can use the `xxd -p` command:

Decoding

```shell-session
ka3n7x@htb[/htb]$ echo https://www.hackthebox.eu/ | xxd -p

68747470733a2f2f7777772e6861636b746865626f782e65752f0a
```

#### Hex Decode

To decode a `hex` encoded string, we can use the `xxd -p -r` command:

Decoding

```shell-session
ka3n7x@htb[/htb]$ echo 68747470733a2f2f7777772e6861636b746865626f782e65752f0a | xxd -p -r

https://www.hackthebox.eu/
``` 

#### Spotting Caesar/Rot13
#### Rot13 Encode

There isn't a specific command in Linux to do `rot13` encoding. However, it is fairly easy to create our own command to do the character shifting:

Decoding

```shell-session
ka3n7x@htb[/htb]$ echo https://www.hackthebox.eu/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'

uggcf://jjj.unpxgurobk.rh/
```

#### Rot13 Decode

We can use the same previous command to decode rot13 as well:

Decoding

```shell-session
ka3n7x@htb[/htb]$ echo uggcf://jjj.unpxgurobk.rh/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'

https://www.hackthebox.eu/
```

Another option to encode/decode rot13 would be using an online tool, like [rot13](https://rot13.com/).

Some tools can help us automatically determine the type of encoding, like [Cipher Identifier](https://www.boxentriq.com/code-breaking/cipher-identifier).
#### Questions

Answer the question(s) below to complete this Section and earn cubes!


+ 1 Using what you learned in this section, determine the type of encoding used in the string you got at previous exercise, and decode it. To get the flag, you can send a 'POST' request to 'serial.php', and set the data as "serial=YOUR_DECODED_OUTPUT".
+ `HTB{ju57_4n07h3r_r4nd0m_53r14l}`
```bash
echo "N2gxNV8xNV9hX3MzY3IzN19tMzU1NGcz"|base64 -d       
7h15_15_a_s3cr37_m3554g3#                
```

```bash
curl -X POST http://94.237.56.187:48627/serial.php -d serial=7h15_15_a_s3cr37_m3554g3 
HTB{ju57_4n07h3r_r4nd0m_53r14l}#                             
```
![[Pasted image 20250109045643.png]]

# Skills Assessment

#### Questions


+ 1 Try to study the HTML code of the webpage, and identify used JavaScript code within it. What is the name of the JavaScript file being used?
	`api.min.js` 
+ 1 Once you find the JavaScript code, try to run it to see if it does any interesting functions. Did you get something in return?
	`HTB{j4v45cr1p7_3num3r4710n_15_k3y}`
	![[Pasted image 20250109050319.png]]
+ 1 As you may have noticed, the JavaScript code is obfuscated. Try applying the skills you learned in this module to deobfuscate the code, and retrieve the 'flag' variable.
	`HTB{n3v3r_run_0bfu5c473d_c0d3!}` 
	![[Pasted image 20250109050229.png]]
	
+ 1 Try to Analyze the deobfuscated JavaScript code, and understand its main functionality. Once you do, try to replicate what it's doing to get a secret key. What is the key?
	`4150495f70336e5f37333537316e365f31355f66756e` 
	![[Pasted image 20250109050614.png]]
+ 2 Once you have the secret key, try to decide it's encoding method, and decode it. Then send a 'POST' request to the same previous page with the decoded key as "key=DECODED_KEY". What is the flag you got?
	`HTB{r34dy_70_h4ck_my_w4y_1n_2_HTB}`
	![[Pasted image 20250109050912.png]]

```bash
curl -X POST http://83.136.252.206:57667/keys.php -d key=API_p3n_73571n6_15_fun 
HTB{r34dy_70_h4ck_my_w4y_1n_2_HTB}                                    
```




# END
# Commands

|**Command**|**Description**|
|---|---|
|`curl http:/SERVER_IP:PORT/`|cURL GET request|
|`curl -s http:/SERVER_IP:PORT/ -X POST`|cURL POST request|
|`curl -s http:/SERVER_IP:PORT/ -X POST -d "param1=sample"`|cURL POST request with data|
|`echo hackthebox \| base64`|base64 encode|
|`echo ENCODED_B64 \| base64 -d`|base64 decode|
|`echo hackthebox \| xxd -p`|hex encode|
|`echo ENCODED_HEX \| xxd -p -r`|hex decode|
|`echo hackthebox \| tr 'A-Za-z' 'N-ZA-Mn-za-m'`|rot13 encode|
|`echo ENCODED_ROT13 \| tr 'A-Za-z' 'N-ZA-Mn-za-m'`|rot13 decode|

# Deobfuscation Websites

|**Website**|
|---|
|[JS Console](https://jsconsole.com)|
|[Prettier](https://prettier.io/playground/)|
|[Beautifier](https://beautifier.io/)|
|[JSNice](http://www.jsnice.org/)|

# Misc

|**Command**|**Description**|
|---|---|
|`ctrl+u`|Show HTML source code in Firefox|