package cn.isekai.keycloak.federation.ucenter;

import cn.isekai.keycloak.federation.ucenter.model.UserData;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.*;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;

import java.sql.*;
import java.util.*;
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

    private Connection getConnection(){
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            return DriverManager.getConnection(config.getJdbcUrl(), config.getDbUser(), config.getDbPass());
        } catch (Exception e){
            logger.error("Cannot connect to UCenter database", e);
        }
        return null;
    }

    public UserData getUser(String findBy, String condition, RealmModel realm){
        return getUser(findBy, condition, String.class, realm);
    }

    public UserData getUser(String findBy, int condition, RealmModel realm){
        return getUser(findBy, condition, Integer.class, realm);
    }

    public UserData getUser(String findBy, Object condition, Class conditionType, RealmModel realm){
        //Connection connection = getConnection();
        PreparedStatement stmt = null;
        UserData userData = null;
        String table;

        try	{
            table = config.getTable("members");
            stmt = dbConnection.prepareStatement("select * from `" + table + "` where `" + findBy + "`=?");

            if(conditionType.equals(String.class)){
                stmt.setString(1, (String) condition);
            } else if(conditionType.equals(Integer.class)){
                stmt.setInt(1, (int) condition);
            }

            ResultSet rs = stmt.executeQuery();
            if(rs.next()){
                //找到用户
                userData = new UserData(this.session, realm, this.model);
                userData.setUserId(rs.getString("uid"));
                userData.setEmail(rs.getString("email"));
                userData.setUsername(rs.getString("username"));
                userData.setPasswordHash(rs.getString("password"), rs.getString("salt"));
                userData.setCreatedTimestamp(rs.getLong("regdate") * 1000);
            }
        } catch(Exception e) {
            logger.error("Find UCenter User Error", e);
        } finally {
            try {
                if(stmt != null) {
                    stmt.close();
                }
                /*if(connection != null){
                    connection.close();
                }*/
            } catch(Exception ignored) {

            }
        }
        return userData;
    }

    @Override
    public UserModel getUserByUsername(String username, RealmModel realm) {
        UserData userData = this.getUser("username", username, realm);
        if(userData == null){
            logger.info("Cannot find user from UCenter Database by username: " + username);
            return null;
        }
        return userData.getLocalUser(realm);
    }

    @Override
    public UserModel getUserByEmail(String email, RealmModel realm) {
        UserData userData = this.getUser("email", email, realm);
        if(userData == null){
            logger.info("Cannot find user from UCenter Database by email: " + email);
            return null;
        }
        return userData.getLocalUser(realm);
    }

    @Override
    public UserModel getUserById(String id, RealmModel realm) {
        return null;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput passwd) {
        Stream<CredentialModel> credentialModelListStream = session.userCredentialManager()
                .getStoredCredentialsByTypeStream(realm, user, PasswordCredentialModel.TYPE);

        //获取UCenter用户
        String uidStr = user.getFirstAttribute("ucenter-uid");
        UserData ucenterUser;
        if(uidStr != null){
            ucenterUser = getUser("uid", Integer.parseInt(uidStr), realm);
        } else {
            ucenterUser = getUser("username", user.getUsername(), realm);
        }

        if(ucenterUser == null) return false;

        boolean fullSync = this.config.getFullSyncEnabled();

        if(fullSync){
            if(ucenterUser.validatePassword(passwd.getChallengeResponse())){
                if (credentialModelListStream != null) {
                    Optional<CredentialModel> storedPasswordOptional = credentialModelListStream.findFirst();
                    if(storedPasswordOptional.isPresent()) {
                        PasswordCredentialModel storedPassword = PasswordCredentialModel
                                .createFromCredentialModel(storedPasswordOptional.get());
                        PasswordHashProvider hash = session.getProvider(PasswordHashProvider.class,
                                storedPassword.getPasswordCredentialData().getAlgorithm());
                        if (hash != null && !hash.verify(passwd.getChallengeResponse(), storedPassword)) {
                            session.userCredentialManager().updateCredential(realm, user, passwd); //更新储存的密码
                        }
                    }
                }
                return true;
            }
        } else {
            if (credentialModelListStream != null && credentialModelListStream.count() > 0) { //使用本地账号验证
                return false;
            }
            if(ucenterUser.validatePassword(passwd.getChallengeResponse())){
                session.userCredentialManager().updateCredential(realm, user, passwd); //更新储存的密码
                return true;
            }
        }
        return false;
    }

    /**
     * 更新UCenter密码
     * @param realm
     * @param user
     * @param input
     * @return
     */
    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if(input.getType().equals(PasswordCredentialModel.TYPE) && user.getFederationLink().equals(this.model.getId()) &&
                this.config.getFullSyncEnabled()){ //完全同步模式，更改ucenter中的用户密码
            String uidStr = user.getFirstAttribute("ucenter-uid");
            if(uidStr == null) return false;

            String salt = UCenterUtils.makeSalt();
            String passwordHash = UCenterUtils.makeHash(input.getChallengeResponse(), salt);

            //Connection connection = getConnection();
            PreparedStatement stmt = null;
            String table;

            boolean result = false;
            try	{
                table = config.getTable("members");
                stmt = dbConnection.prepareStatement("update `" + table + "` set `password`=?, `salt`=? where `uid`=?");

                stmt.setString(1, passwordHash);
                stmt.setString(2, salt);
                stmt.setInt(3, Integer.parseInt(uidStr));

                result = stmt.execute();
            } catch(Exception e) {
                logger.error("Failed to update user password at UCenter", e);
            } finally {
                try {
                    if(stmt != null) {
                        stmt.close();
                    }
                    /*if(connection != null){
                        connection.close();
                    }*/
                } catch(Exception ignored) {

                }
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
    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        return Collections.EMPTY_SET;
    }

    @Override
    public void close() {
        try {
            dbConnection.close();
        } catch (SQLException ignored) {

        }
    }
}