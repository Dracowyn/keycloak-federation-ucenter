package cn.isekai.keycloak.federation.ucenter;

import cn.isekai.keycloak.federation.ucenter.model.UserData;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.*;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;

import java.sql.*;
import java.util.stream.Stream;

public class UCenterFederationProvider implements UserStorageProvider,
        UserLookupProvider,
        CredentialInputValidator,
        CredentialInputUpdater {
    private static final Logger logger = Logger.getLogger(UCenterFederationProvider.class);

    protected KeycloakSession session;
    protected ComponentModel model;
    protected UCenterConfig config;
    protected UCenterFederationProviderFactory factory;

    protected Connection dbConnection;

    public UCenterFederationProvider(KeycloakSession session, ComponentModel model,
                                     UCenterFederationProviderFactory factory) {
        this.session = session;
        this.model = model;
        this.config = new UCenterConfig(model);
        this.factory = factory;

        this.dbConnection = getConnection();
    }

    private Connection getConnection() {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            return DriverManager.getConnection(config.getJdbcUrl(), config.getDbUser(), config.getDbPass());
        } catch (Exception e) {
            logger.error("Can not connect to UCenter database", e);
        }
        return null;
    }

    public UserData getUser(String findBy, String condition, RealmModel realm) {
        return getUser(findBy, condition, String.class, realm);
    }

    public UserData getUser(String findBy, int condition, RealmModel realm) {
        return getUser(findBy, condition, Integer.class, realm);
    }

    /**
     * 根据条件获取UCenter用户
     *
     * @param findBy        username/email/uid
     * @param condition     条件值
     * @param conditionType 条件类型
     * @param realm         RealmModel
     * @return UserData
     */
    public UserData getUser(String findBy, Object condition, Class<?> conditionType, RealmModel realm) {
        // 初始化返回值
        UserData userData = null;

        try {
            // 获取表名
            String table = config.getTable("members");

            try (var stmt = dbConnection.prepareStatement("SELECT * FROM `" + table + "` WHERE `" + findBy + "`=?")) {
                // 根据条件类型设置查询参数
                if (conditionType.equals(String.class)) {
                    stmt.setString(1, (String) condition);
                } else if (conditionType.equals(Integer.class)) {
                    stmt.setInt(1, (Integer) condition);
                }

                // 执行查询并处理结果集
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        // 找到用户
                        userData = new UserData(this.session, realm, this.model);
                        userData.setUserId(rs.getString("uid"));
                        userData.setEmail(rs.getString("email"));
                        userData.setUsername(rs.getString("username"));
                        userData.setPasswordHash(rs.getString("password"), rs.getString("salt"));
                        userData.setCreatedTimestamp(rs.getLong("regdate") * 1000);
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Find UCenter User Error", e);
        }

        return userData;
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        UserData userData = this.getUser("username", username, realm);
        if (userData == null) {
            logger.info("Cannot find user from UCenter Database by username: " + username);
            return null;
        }
        return userData.getLocalUser(realm);
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        UserData userData = this.getUser("email", email, realm);
        if (userData == null) {
            logger.info("Cannot find user from UCenter Database by email: " + email);
            return null;
        }
        return userData.getLocalUser(realm);
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        return null;
    }

    /**
     * 验证密码方法，当启用完全同步模式时，如果本地存储的密码和UCenter用户的密码不匹配，更新本地存储的密码
     * 当禁用完全同步模式时，只有当没有本地账户时才使用UCenter用户验证
     *
     * @param realm  RealmModel
     * @param user   UserModel
     * @param passwd CredentialInput
     * @return boolean
     */
    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput passwd) {
        // 从存储的凭据中获取密码凭据流
        Stream<CredentialModel> credentialModelListStream = user.credentialManager()
                .getStoredCredentialsByTypeStream(PasswordCredentialModel.TYPE);
        // 根据用户属性获取UCenter用户
        String uidStr = user.getFirstAttribute("ucenter-uid");
        UserData ucenterUser;
        if (uidStr != null) {
            ucenterUser = getUser("uid", Integer.parseInt(uidStr), realm);
        } else {
            ucenterUser = getUser("username", user.getUsername(), realm);
        }

        // 如果UCenter用户不存在，验证失败
        if (ucenterUser == null) {
            return false;
        }
        // 查看配置是否启用完全同步模式
        boolean fullSync = this.config.getFullSyncEnabled();
        if (fullSync) {
            // 当完全同步模式启用时，如果UCenter用户密码验证成功
            if (ucenterUser.validatePassword(passwd.getChallengeResponse())) {
                // 验证存储的密码并在需要时更新
                credentialModelListStream.findFirst().ifPresent(credentialModel -> {
                    PasswordCredentialModel storedPassword = PasswordCredentialModel
                            .createFromCredentialModel(credentialModel);
                    PasswordHashProvider hash = session.getProvider(PasswordHashProvider.class,
                            storedPassword.getPasswordCredentialData().getAlgorithm());
                    if (hash != null && !hash.verify(passwd.getChallengeResponse(), storedPassword)) {
                        // 如果本地存储的密码和UCenter用户的密码不匹配，更新本地存储的密码
                        user.credentialManager().updateCredential(passwd);
                    }
                });
                return true;
            }
        } else {
            // 当完全同步模式禁用时，只有当没有本地账户时才使用UCenter用户验证
            if (credentialModelListStream.findAny().isEmpty() &&
                    ucenterUser.validatePassword(passwd.getChallengeResponse())) {
                // 如果UCenter用户密码验证成功，更新本地存储的密码
                user.credentialManager().updateCredential(passwd);
                return true;
            }
        }
        return false;
    }

    /**
     * 更新UCenter密码
     *
     * @param realm RealmModel
     * @param user  UserModel
     * @param input CredentialInput
     * @return boolean
     */
    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        //如果输入类型为密码并且用户的联合链接等于此模型的ID，并且启用了完全同步则更改ucenter中的用户密码
        if (PasswordCredentialModel.TYPE.equals(input.getType()) && this.model.getId().equals(user.getFederationLink())
                && this.config.getFullSyncEnabled()) {

            String uidStr = user.getFirstAttribute("ucenter-uid");
            if (uidStr == null) {
                return false;
            }

            //创建盐和密码哈希
            // 如果是UCenter 1.7.0 及以上版本，使用bcrypt算法
            String passwordHash;
            String salt;
            if (this.config.ucenter170) {
                passwordHash = UCenterUtils.bcrypt(input.getChallengeResponse());
                salt = null;
            } else {
                salt = UCenterUtils.makeSalt();
                passwordHash = UCenterUtils.makeHash(input.getChallengeResponse(), salt);
            }

            boolean result = false;
            try (var stmt = dbConnection.prepareStatement(
                    "UPDATE `" + config.getTable("members") + "` SET `password`=?, `salt`=? WHERE `uid`=?")) {

                stmt.setString(1, passwordHash);
                stmt.setString(2, salt);
                stmt.setInt(3, Integer.parseInt(uidStr));

                result = stmt.execute();

            } catch (Exception e) {
                logger.error("Failed to update user password at UCenter", e);
            }
            return result;
        }
        return false;
    }

    @Override
    public void preRemove(RealmModel realm) {

    }

    @Override
    public void preRemove(RealmModel realm, RoleModel role) {

    }

    @Override
    public void preRemove(RealmModel realm, GroupModel group) {

    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return credentialType.equals(PasswordCredentialModel.TYPE);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return supportsCredentialType(credentialType);
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream(RealmModel realm, UserModel user) {
        return Stream.empty();
    }

    @Override
    public void close() {
        try {
            dbConnection.close();
        } catch (SQLException ignored) {

        }
    }
}