## JAVA反序列化

### 序列化

```java
package com.itheima.serializeable;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;

public class ObjectOutputStreamDemo1 {
    public static void main(String[] args) throws Exception {
        // 1. 创建学生对象
        Student s = new Student("张三", "zs", "pass", 18);

        // 2. 对象序列化：使用对象字节输出流包装字节输出流管道
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("serializable_test/src/obj.txt"));

        // 3. 直接调用序列化方法
        oos.writeObject(s);

        // 4. 释放资源
        oos.close();
        System.out.println("序列化完成");
    }
}

```

+ 被序列化类

> 对象如果要序列化，必须实现Serializabl序列化接口e

```java
package com.itheima.serializeable;

import java.io.Serializable;

/**
 * 对象如果序列化，必须实现Serializable序列化接口
 */
public class Student implements Serializable {
    private String name;
    private String loginName;
    private String password;
    private int age;

    public Student() {
    }

    public Student(String name, String loginName, String password, int age) {
        this.name = name;
        this.loginName = loginName;
        this.password = password;
        this.age = age;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLoginName() {
        return loginName;
    }

    public void setLoginName(String loginName) {
        this.loginName = loginName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    @Override
    public String toString() {
        return "Student{" +
                "name='" + name + '\'' +
                ", loginName='" + loginName + '\'' +
                ", password='" + password + '\'' +
                ", age=" + age +
                '}';
    }
}
```





命令执行 

```java
package com.itheima.demo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class Exec {
    public static void main(String[] args) throws IOException, InterruptedException {
        Process p = Runtime.getRuntime().exec("whoami");
        java.io.InputStream is = p.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        p.waitFor();
        if (p.exitValue() != 0) {
            // 命令执行失败，进入处理程序
        }
        String s = null;
        while ((s = reader.readLine()) != null) {
            System.out.println(s);
        }
    }
}
```



java -jar 