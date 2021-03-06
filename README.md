# Keycloak federation for UCenter
这个程序可以将ucenter的用户合并到keycloak（但是只会合并账号基础信息）

## 配置方法
先在standalone.xml的 ```<datasources></datasources>``` 中添加UCener的数据源
```xml
<datasource jndi-name="java:jboss/datasources/UCenter-Federation" pool-name="UCenter-Federation" enabled="true" use-java-context="true" jta="false">
    <connection-url>jdbc:mysql://localhost:3306/ucenter?useSSL=false&amp;serverTimezone=GMT%2B8&amp;characterEncoding=UTF-8</connection-url>
    <driver>mysql</driver>
    <security>
        <user-name>root</user-name>
        <password>root</password>
    </security>
</datasource>
```

然后在Keycloak的后台中添加User Federation，选择ucenter，在JNDI中填写配置文件中写的JNDI（如：```java:jboss/datasources/UCenter-Federation```）