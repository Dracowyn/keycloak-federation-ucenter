package cn.isekai.keycloak.federation.ucenter.model;

import cn.isekai.keycloak.federation.ucenter.UCenterFederationProvider;
import cn.isekai.keycloak.federation.ucenter.UCenterUtils;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStoragePrivateUtil;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;

public class UserData extends AbstractUserAdapterFederatedStorage  implements UserModel  {
    private static final Logger logger = Logger.getLogger(UCenterFederationProvider.class);
    private final ComponentModel model;

    public UserData(KeycloakSession session, RealmModel realm,
                    ComponentModel storageProviderModel) {
        super(session, realm, storageProviderModel);
        model = storageProviderModel;

        this.setEnabled(true);
        this.setEmailVerified(true);
    }

    protected String userId, email, userName, passwordHash, salt;
    protected Long createdTime;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    @Override
    public Long getCreatedTimestamp() {
        return System.currentTimeMillis();
    }

    @Override
    public String getId() {
        if (storageId == null) {
            storageId = new StorageId(model.getId(), this.userId);
        }
        return storageId.getId();
    }

    @Override
    public String getFirstName() {
        return this.userName;
    }

    @Override
    public String getLastName() {
        return "";
    }

    @Override
    public String getUsername() {
        return this.userName;
    }

    @Override
    public void setUsername(String username) {
        this.userName = username;
    }

    public void setPasswordHash(String passwordHash, String salt){
        this.passwordHash = passwordHash;
        this.salt = salt;
    }

    public boolean validatePassword(String password){
        return UCenterUtils.validatePassword(password, this.passwordHash, this.salt);
    }

    @Override
    public boolean isEmailVerified() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }


    @Override
    public void setCreatedTimestamp(Long timestamp) {
        this.createdTime = timestamp;
    }

    @Override
    public String getEmail() {
        return email;
    }

    @Override
    public void setEmail(String email) {
        this.email = email;
    }

    public UserModel getLocalUser(RealmModel realm){
        UserModel localUser = UserStoragePrivateUtil.userLocalStorage(session).getUserByUsername(realm, this.getUsername());
        if(localUser == null) {
            logger.info("Local user not found, auto-create: " + this.getUsername());
            localUser = UserStoragePrivateUtil.userLocalStorage(session).addUser(realm, this.getUsername());
            localUser.setFederationLink(model.getId());
            localUser.setEmail(this.getEmail());
            localUser.setUsername(this.getUsername());
            localUser.setCreatedTimestamp(this.getCreatedTimestamp());
            localUser.setFirstName(this.getUsername());
            localUser.setEnabled(true);
            localUser.setEmailVerified(true);
            localUser.setSingleAttribute("ucenter-uid", this.getUserId());
            return localUser;
        }
        return localUser;
    }
}