
- [Web Requests](https://academy.hackthebox.com/module/details/35) 


### Types of headers 
## General Headers

[General headers](https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html) are used in both HTTP requests and responses. They are contextual and are used to `describe the message rather than its contents`.

| **Header** | **Example** | **Description** |
| --- | --- | --- |
| `Date` | `Date: Wed, 16 Feb 2022 10:38:44 GMT` | Holds the date and time at which the message originated. It's preferred to convert the time to the standard [UTC](https://en.wikipedia.org/wiki/Coordinated_Universal_Time) time zone. |
| `Connection` | `Connection: close` | Dictates if the current network connection should stay alive after the request finishes. Two commonly used values for this header are `close` and `keep-alive`. The `close` value from either the client or server means that they would like to terminate the connection, while the `keep-alive` header indicates that the connection should remain open to receive more data and input. |

* * *

## Entity Headers

Similar to general headers, [Entity Headers](https://www.w3.org/Protocols/rfc2616/rfc2616-sec7.html) can be `common to both the request and response`. These headers are used to `describe the content` (entity) transferred by a message. They are usually found in responses and POST or PUT requests.

| **Header**         | **Example**                   | **Description**                                                                                                                                                                                                                                                            |
| ------------------ | ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Content-Type`     | `Content-Type: text/html`     | Used to describe the type of resource being transferred. The value is automatically added by the browsers on the client-side and returned in the server response. The `charset` field denotes the encoding standard, such as [UTF-8](https://en.wikipedia.org/wiki/UTF-8). |
| `Media-Type`       | `Media-Type: application/pdf` | The `media-type` is similar to `Content-Type`, and describes the data being transferred. This header can play a crucial role in making the server interpret our input. The `charset` field may also be used with this header.                                              |
| `Boundary`         | `boundary="b4e4fbd93540"`     | Acts as a marker to separate content when there is more than one in the same message. For example, within a form data, this boundary gets used as `--b4e4fbd93540` to separate different parts of the form.                                                                |
| `Content-Length`   | `Content-Length: 385`         | Holds the size of the entity being passed. This header is necessary as the server uses it to read data from the message body, and is automatically generated by the browser and tools like cURL.                                                                           |
| `Content-Encoding` | `Content-Encoding: gzip`      | Data can undergo multiple transformations before being passed. For example, large amounts of data can be compressed to reduce the message size. The type of encoding being used should be specified using the `Content-Encoding` header.                                   |

* * *

## Request Headers

The client sends [Request Headers](https://tools.ietf.org/html/rfc2616) in an HTTP transaction. These headers are `used in an HTTP request and do not relate to the content` of the message. The following headers are commonly seen in HTTP requests.

| **Header**      | **Example**                              | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| --------------- | ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Host`          | `Host: www.inlanefreight.com`            | Used to specify the host being queried for the resource. This can be a domain name or an IP address. HTTP servers can be configured to host different websites, which are revealed based on the hostname. This makes the host header an important enumeration target, as it can indicate the existence of other hosts on the target server.                                                                                                                          |
| `User-Agent`    | `User-Agent: curl/7.77.0`                | The `User-Agent` header is used to describe the client requesting resources. This header can reveal a lot about the client, such as the browser, its version, and the operating system.                                                                                                                                                                                                                                                                              |
| `Referer`       | `Referer: http://www.inlanefreight.com/` | Denotes where the current request is coming from. For example, clicking a link from Google search results would make `https://google.com` the referer. Trusting this header can be dangerous as it can be easily manipulated, leading to unintended consequences.                                                                                                                                                                                                    |
| `Accept`        | `Accept: */*`                            | The `Accept` header describes which media types the client can understand. It can contain multiple media types separated by commas. The `*/*` value signifies that all media types are accepted.                                                                                                                                                                                                                                                                     |
| `Cookie`        | `Cookie: PHPSESSID=b4e4fbd93540`         | Contains cookie-value pairs in the format `name=value`. A [cookie](https://en.wikipedia.org/wiki/HTTP_cookie) is a piece of data stored on the client-side and on the server, which acts as an identifier. These are passed to the server per request, thus maintaining the client's access. Cookies can also serve other purposes, such as saving user preferences or session tracking. There can be multiple cookies in a single header separated by a semi-colon. |
| `Authorization` | `Authorization: BASIC cGFzc3dvcmQK`      | Another method for the server to identify clients. After successful authentication, the server returns a token unique to the client. Unlike cookies, tokens are stored only on the client-side and retrieved by the server per request. There are multiple types of authentication types based on the webserver and application type used.                                                                                                                           |

A complete list of request headers and their usage can be found [here](https://tools.ietf.org/html/rfc7231#section-5).

* * *

## Response Headers

[Response Headers](https://tools.ietf.org/html/rfc7231#section-7) can be `used in an HTTP response and do not relate to the content`. Certain response headers such as `Age`, `Location`, and `Server` are used to provide more context about the response. The following headers are commonly seen in HTTP responses.

| **Header** | **Example** | **Description** |
| --- | --- | --- |
| `Server` | `Server: Apache/2.2.14 (Win32)` | Contains information about the HTTP server, which processed the request. It can be used to gain information about the server, such as its version, and enumerate it further. |
| `Set-Cookie` | `Set-Cookie: PHPSESSID=b4e4fbd93540` | Contains the cookies needed for client identification. Browsers parse the cookies and store them for future requests. This header follows the same format as the `Cookie` request header. |
| `WWW-Authenticate` | `WWW-Authenticate: BASIC realm="localhost"` | Notifies the client about the type of authentication required to access the requested resource. |

* * *

## Security Headers

Finally, we have [Security Headers](https://owasp.org/www-project-secure-headers/). With the increase in the variety of browsers and web-based attacks, defining certain headers that enhanced security was necessary. HTTP Security headers are `a class of response headers used to specify certain rules and policies` to be followed by the browser while accessing the website.

| **Header** | **Example** | **Description** |
| --- | --- | --- |
| `Content-Security-Policy` | `Content-Security-Policy: script-src 'self'` | Dictates the website's policy towards externally injected resources. This could be JavaScript code as well as script resources. This header instructs the browser to accept resources only from certain trusted domains, hence preventing attacks such as [Cross-site scripting (XSS)](https://en.wikipedia.org/wiki/Cross-site_scripting). |
| `Strict-Transport-Security` | `Strict-Transport-Security: max-age=31536000` | Prevents the browser from accessing the website over the plaintext HTTP protocol, and forces all communication to be carried over the secure HTTPS protocol. This prevents attackers from sniffing web traffic and accessing protected information such as passwords or other sensitive data. |
| `Referrer-Policy` | `Referrer-Policy: origin` | Dictates whether the browser should include the value specified via the `Referer` header or not. It can help in avoiding disclosing sensitive URLs and information while browsing the website. |

**Note:** This section only mentions a small subset of commonly seen HTTP headers. There are many other contextual headers that can be used in HTTP communications. It's also possible for applications to define custom headers based on their requirements. A complete list of standard HTTP headers can be found [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers).

## Request Methods

The following are some of the commonly used methods:

| **Method** | **Description** |
| --- | --- |
| `GET` | Requests a specific resource. Additional data can be passed to the server via query strings in the URL (e.g. `?param=value`). |
| `POST` | Sends data to the server. It can handle multiple types of input, such as text, PDFs, and other forms of binary data. This data is appended in the request body present after the headers. The POST method is commonly used when sending information (e.g. forms/logins) or uploading data to a website, such as images or documents. |
| `HEAD` | Requests the headers that would be returned if a GET request was made to the server. It doesn't return the request body and is usually made to check the response length before downloading resources. |
| `PUT` | Creates new resources on the server. Allowing this method without proper controls can lead to uploading malicious resources. |
| `DELETE` | Deletes an existing resource on the webserver. If not properly secured, can lead to Denial of Service (DoS) by deleting critical files on the web server. |
| `OPTIONS` | Returns information about the server, such as the methods accepted by it. |
| `PATCH` | Applies partial modifications to the resource at the specified location. |

The list only highlights a few of the most commonly used HTTP methods. The availability of a particular method depends on the server as well as the application configuration. For a full list of HTTP methods, you can visit this [link](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods).

**Note:** Most modern web applications mainly rely on the `GET` and `POST` methods. However, any web application that utilizes REST APIs also rely on `PUT` and `DELETE`, which are used to update and delete data on the API endpoint, respectively. Refer to the [Introduction to Web Applications](/module/details/75) module for more details.

* * *

## Response Codes

HTTP status codes are used to tell the client the status of their request. An HTTP server can return five types of response codes:

| **Type** | **Description** |
| --- | --- |
| `1xx` | Provides information and does not affect the processing of the request. |
| `2xx` | Returned when a request succeeds. |
| `3xx` | Returned when the server redirects the client. |
| `4xx` | Signifies improper requests `from the client`. For example, requesting a resource that doesn't exist or requesting a bad format. |
| `5xx` | Returned when there is some problem `with the HTTP server` itself. |

The following are some of the commonly seen examples from each of the above HTTP method types:

| **Code** | **Description** |
| --- | --- |
| `200 OK` | Returned on a successful request, and the response body usually contains the requested resource. |
| `302 Found` | Redirects the client to another URL. For example, redirecting the user to their dashboard after a successful login. |
| `400 Bad Request` | Returned on encountering malformed requests such as requests with missing line terminators. |
| `403 Forbidden` | Signifies that the client doesn't have appropriate access to the resource. It can also be returned when the server detects malicious input from the user. |
| `404 Not Found` | Returned when the client requests a resource that doesn't exist on the server. |
| `500 Internal Server Error` | Returned when the server cannot process the request. |


### Curl 
```
curl -u # --user -> add user:pass for js prompt
curl -i # --include -> Include response headers in the output.
curl -k # --insecure -> Ignore Cert Exchange
curl -v # --verbose -> More verbose (See the Request and Response)
curl -b # --cookie -> Pass the data to the HTTP server in the Cookie header.
curl -d # --data -> Sends the specified data in a POST request to the HTTP server,
curl -s # --slient -> Quiet mode, Do not show the progress bar
curl -X # --request -> Specify Request method (GET, POST etc...)
```

