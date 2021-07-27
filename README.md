# Keycloak federation for UCenter
这个程序可以将ucenter的用户合并到keycloakX（但是只会合并账号基础信息）

## 打包方法
进入本项目目录执行命令```mvn assembly:assembly```

## 配置方法
1. 打包完成后将target目录下keycloak-federation-ucenter-版本号-jar-with-dependencies.jar复制进keycloak根目录下的providers目录。
2. 重启KeycloakX
3. 在Keycloak的后台中添加User Federation，选择ucenter，填写好UCenter所在数据库信息（JDBC URL参考：```jdbc:mysql://localhost:3306/ucenter?useSSL=false&serverTimezone=GMT+8&characterEncoding=UTF-8&autoReconnect=true```）
注意修改Table Prefix，此为UCenter表前缀。