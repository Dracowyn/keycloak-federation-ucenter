# Keycloak federation for UCenter
Keycloak UCenter用户同步插件

## 说明
- 可以将ucenter的用户异步迁移到keycloak（但是只会合并账号基础信息）
- 只会在用户第一次使用Discuz原账号密码登录Keycloak时同步用户信息，后续不会再同步。
- 只会迁移用户名、邮箱、密码以及用户UCenter-uid，其它信息不会迁移。
- 兼容Discuz!X3.4（UCenter低于1.7.0）和Discuz!X3.5

## 运行环境
- Java 17
- Keycloak 23.x.x

## 打包方法
执行```mvn package```即可打包，打包后的jar文件在target目录下。

## 配置方法
1. 打包完成后将target目录下keycloak-federation-ucenter-版本号.jar复制进keycloak根目录下的providers目录。
2. 重启Keycloak
3. 在Keycloak的后台中添加User Federation，选择ucenter，填写好UCenter所在数据库信息（JDBC URL参考：```jdbc:mysql://localhost:3306/ucenter?useSSL=false&erverTimezone=GMT%2B8&characterEncoding=UTF-8&autoReconnect=true```）
注意修改Table Prefix，此为UCenter表前缀。