[Back to Contents](README.md)


### 安全检查单

翻译:qiaoy

##### 认证 (注册/登录/双因子/重置密码) 


- [ ] 全站启用Https 
- [ ] 使用Bcrypt对密码进行加密 
- [ ] 用户退出后，销毁会话 
- [ ] 重置密码后，销毁所有尚生效的会话 
- [ ] OAuth2必须启用state参数 
- [ ] 不要在成功登录后，做页面重定向或跳转 
- [ ] 在注册/登录功能处，过滤javascript://,data://,CRLF字符 
- [ ] Cookies设置secure和httpOnly选项 
- [ ] 在使用短信认证时，不将任何短信认证内容放到http相应会话中 
- [ ] 限制对特定用户的登录、验证手机验证码、重发手机验证码、生产手机验证码的API调用，有退避算法或者验证码，避免被暴力破解 
- [ ] 检查邮件、短信中的重置密码会话是否随机 
- [ ] 重置密码会话设置合理的生效时间 
- [ ] 成功重置密码后，销毁已使用的会话 

##### 用户数据 & 授权

- [ ] 任何途径访问类似'购物车'、'历史记录'时，必须根据会话ID检查登录用户的所有权
- [ ] 避免连续的资源ID，使用'/me/orders'而不是'/user/37153/orders'，避免忘记做用户鉴权
- [ ] 修改邮箱/手机号等资料时，需先发送验证用户身份的邮件
- [ ] 任何上传功能都需将用户上传的文件进行重命名，上传文件存储于独立服务，翻译注:可对web中间件用户做权限配置，设置上传目录有写入，无执行权限，其他目录有执行，无写入权限
- [ ] 如无特殊需求，需将上传图片的EXIF标记清除
- [ ] For user ids and other ids, use [RFC compliant ](http://www.ietf.org/rfc/rfc4122.txt) `UUID` instead of integers. You can find an implementation for this for your language on Github.
- [ ] 独立的应用或接口，需使用JSON Web Token


##### ANDROID / IOS APP

- [ ] 支付通道的salt必能硬编码
- [ ] 第三方SDK的secret和认证令牌不能硬编码
- [ ] API calls intended to be done `server to server` should not be done from the app.
- [ ] In Android, all the granted  [permissions](https://developer.android.com/guide/topics/security/permissions.html) should be carefully evaluated.
- [ ] [Certificate pinning](https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning) is highly recommended.


##### Http头安全 & 配置

- [ ] `Add` [CSP](https://en.wikipedia.org/wiki/Content_Security_Policy) header to mitigate XSS and data injection attacks. This is important.
- [ ] `Add` [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) header to prevent cross site request forgery. Also add [SameSite](https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site-00) attributes on cookies.
- [ ] `Add` [HSTS](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security) header to prevent SSL stripping attack.
- [ ] `Add` your domain to the [HSTS Preload List](https://hstspreload.appspot.com/)
- [ ] `Add` [X-Frame-Options](https://en.wikipedia.org/wiki/Clickjacking#X-Frame-Options) to protect against Clickjacking.
- [ ] `Add` [X-XSS-Protection](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#X-XSS-Protection) header to mitigate XSS attacks.
- [ ] Update DNS records to add [SPF](https://en.wikipedia.org/wiki/Sender_Policy_Framework) record to mitigate spam and phishing attacks.
- [ ] Add [subresource integrity checks](https://en.wikipedia.org/wiki/Subresource_Integrity) if loading your JavaScript libraries from a third party CDN.
- [ ] Use random CSRF tokens and expose business logic APIs as HTTP POST requests. Do not expose CSRF tokens over HTTP for example in an initial request upgrade phase.
- [ ] Do not use critical data or tokens in GET request parameters. Exposure of server logs or a machine/stack processing them would expose user data in turn.

##### 输入过滤

- [ ] `Sanitize` all user inputs or any input parameters exposed to user to prevent [XSS](https://en.wikipedia.org/wiki/Cross-site_scripting).
- [ ] `Sanitize` all user inputs or any input parameters exposed to user to prevent [SQL Injection](https://en.wikipedia.org/wiki/SQL_injection).
- [ ] Sanitize user input if using it directly for functionalities like CSV import.
- [ ] `Sanitize` user input for special cases like robots.txt as profile names in case you are using a url pattern like coolcorp.io/username. 
- [ ] Do not hand code or build JSON by string concatenation ever, no matter how small the object is. Use your language defined libraries or framework.
- [ ] Sanitize inputs that take some sort of URLs to prevent [SSRF](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit#heading=h.t4tsk5ixehdd).
- [ ] Sanitize Outputs before displaying to users.

##### 运维安全

- [ ] If you are small and inexperienced, evaluate using AWS elasticbeanstalk or a PaaS to run your code.
- [ ] Use a decent provisioning script to create VMs in the cloud.
- [ ] Check for machines with unwanted publicly `open ports`.
- [ ] Check for no/default passwords for `databases` especially MongoDB & Redis.
- [ ] Use SSH to access your machines; do not setup a password.
- [ ] Install updates timely to act upon zero day vulnerabilities like Heartbleed, Shellshock.
- [ ] Modify server config to use TLS 1.2 for HTTPS and disable all other schemes. (The tradeoff is good.)
- [ ] Do not leave the DEBUG mode on. In some frameworks, DEBUG mode can give access full-fledged REPL or shells or expose critical data in error messages stacktraces.
- [ ] Be prepared for bad actors & DDOS - use [Cloudflare](https://www.cloudflare.com/ddos/).
- [ ] Set up monitoring for your systems, and log stuff (use [New Relic](https://newrelic.com/) or something like that).
- [ ] If developing for enterprise customers, adhere to compliance requirements. If AWS S3, consider using the feature to [encrypt data](http://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html). If using AWS EC2, consider using the feature to use encrypted volumes (even boot volumes can be encrypted now).

##### 人员

- [ ] Set up an email (e.g. security@coolcorp.io) and a page for security researchers to report vulnerabilities.
- [ ] Depending on what you are making, limit access to your user databases.
- [ ] Be polite to bug reporters.
- [ ] Have your code review done by a fellow developer from a secure coding perspective. (More eyes)
- [ ] In case of a hack or data breach, check previous logs for data access, ask people to change passwords. You might require an audit by external agencies depending on where you are incorporated.  
- [ ] Set up [Netflix's Scumblr](https://github.com/Netflix/Scumblr) to hear about talks about your organization on social platforms and Google search.
