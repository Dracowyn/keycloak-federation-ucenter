# Keycloak federation for UCenter
这个程序可以将ucenter的用户合并到keycloak（但是只会合并账号基础信息）

## 打包方法
进入本项目目录执行命令```mvn assembly:assembly```

## 配置方法
打包完成后将target目录下keycloak-federation-ucenter-版本号-jar-with-dependencies.jar复制进keycloak根目录下的providers目录，
并在standalone.xml的 ```<datasources></datasources>``` 中添加UCener的数据源
```xml
<datasource jndi-name="java:jboss/datasources/UCenter-Federation" pool-name="UCenter-Federation" enabled="true" use-java-context="true" jta="false">
    <connection-url>jdbc:mysql://localhost:3306/UCenter数据库?useSSL=false&amp;serverTimezone=GMT%2B8&amp;characterEncoding=UTF-8</connection-url>
    <driver>mysql</driver>
    <security>
        <user-name>数据库账号</user-name>
        <password>数据库密码</password>
    </security>
</datasource>
```

然后在Keycloak的后台中添加User Federation，选择ucenter，在JNDI中填写配置文件中写的JNDI（如：```java:jboss/datasources/UCenter-Federation```）如果正常该项会自动填写完成。
注意修改Table Prefix，此为UCenter表前缀