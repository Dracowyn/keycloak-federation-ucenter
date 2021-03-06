package cn.isekai.keycloak.federation.ucenter;

import cn.isekai.keycloak.federation.ucenter.model.UserData;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;

import javax.naming.InitialContext;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class UCenterFederationProvider implements UserStorageProvider,
        UserLookupProvider,
        CredentialInputValidator {
    private static final Logger logger = Logger.getLogger(UCenterFederationProvider.class);

    protected KeycloakSession session;
    protected ComponentModel model;
    protected UCenterConfig config;
    protected UCenterFederationProviderFactory factory;

    public UCenterFederationProvider(KeycloakSession session, ComponentModel model,
                                     UCenterFederationProviderFactory factory) {
        this.session = session;
        this.model = model;
        this.config = new UCenterConfig(model);
        this.factory = factory;
    }

    public UserData getUser(String findBy, String condition, RealmModel realm){
        Connection dbw = null;
        PreparedStatement stmt = null;
        UserData userData = null;
        String table;

        try	{
            InitialContext ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup(config.getDataSourceName());
            table = config.getTable("members");
            dbw = ds.getConnection();
            stmt = dbw.prepareStatement("select * from " + table + " where `" + findBy + "`=?");
            stmt.setString(1, condition);

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
                if(dbw != null) {
                    dbw.close();
                }
            } catch(Exception ignored) {

            }
        }
        return userData;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput passwd) {
        UserData userData = null;
        if(user.getUsername() != null){
            //先查找本地是否存在用户，存在就跳过
            UserModel localUser = session.userLocalStorage().getUserByUsername(user.getUsername(), realm);
            if(localUser != null) return false;
            userData = this.getUser("username", user.getUsername(), realm);
        } else if(user.getEmail() != null){
            UserModel localUser = session.userLocalStorage().getUserByEmail(user.getEmail(), realm);
            if(localUser != null) return false;
            userData = this.getUser("email", user.getEmail(), realm);
        }

        if(userData != null){
            return userData.validatePassword(passwd.getChallengeResponse());
        }
        return false;
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
    public void close() {

    }
}
