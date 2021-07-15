package cn.isekai.keycloak.federation.ucenter;

import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.representations.idm.ComponentRepresentation;

public class UCenterConfig {
    private static final Logger logger = Logger.getLogger(UCenterFederationProvider.class);
    protected MultivaluedHashMap<String, String> config;

    public String datasourceName;
    public String tablePrefix;
    public boolean fullSync;

    public UCenterConfig(ComponentModel componentModel){
        this.config = componentModel.getConfig();
        this.initialize();
    }

    public UCenterConfig(ComponentRepresentation componentRepresentation){
        this.config = componentRepresentation.getConfig();
        this.initialize();
    }

    protected MultivaluedHashMap<String, String> getConfig() {
        return config;
    }

    protected void initialize(){
        this.datasourceName = config.getFirst("datasource-name");
        this.tablePrefix = config.getFirst("table-prefix");
        this.fullSync = Boolean.parseBoolean(config.getFirst("full-sync"));
        logger.info("Full sync: " + config.getFirst("full-sync"));
    }

    /**
     * 获取DataSource名
     * @return DataSourceName
     */
    public String getDataSourceName(){
        return this.datasourceName;
    }

    /**
     * 获取表前缀
     * @return 表前缀
     */
    public String getTablePrefix(){
        return this.tablePrefix;
    }

    /**
     * 获取完全同步模式的开启状态
     * @return 是否开启完全同步模式
     */
    public boolean getFullSyncEnabled() {
        return this.fullSync;
    }

    /**
     * 获取完整表名
     * @param tableName 原表名
     * @return 带前缀的表名
     */
    public String getTable(String tableName){
        return this.getTablePrefix() + tableName;
    }
}
