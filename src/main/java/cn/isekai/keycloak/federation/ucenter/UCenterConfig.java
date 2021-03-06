package cn.isekai.keycloak.federation.ucenter;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.representations.idm.ComponentRepresentation;

public class UCenterConfig {
    protected MultivaluedHashMap<String, String> config;

    public UCenterConfig(ComponentModel componentModel){
        this.config = componentModel.getConfig();
    }

    public UCenterConfig(ComponentRepresentation componentRepresentation){
        this.config = componentRepresentation.getConfig();
    }

    protected MultivaluedHashMap<String, String> getConfig() {
        return config;
    }

    public String getDataSourceName(){
        return config.getFirst("datasource-name");
    }

    public String getTablePrefix(){
        return config.getFirst("table-prefix");
    }

    public String getTable(String tableName){
        return this.getTablePrefix() + tableName;
    }
}
