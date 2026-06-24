package com.shopsphere.config;

import javax.sql.DataSource;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

/**
 * Database Configuration Class
 * Explicitly configures the H2 in-memory datasource using properties defined in the environment.
 */
@Configuration
public class DataSourceConfig {

    private final Environment env;

    public DataSourceConfig(Environment env) {
        this.env = env;
    }

    @Bean
    public DataSource dataSource() {
        return DataSourceBuilder.create()
                .url(env.getProperty("spring.datasource.url", "jdbc:h2:mem:benchmarkdb;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"))
                .username(env.getProperty("spring.datasource.username", "sa"))
                .password(env.getProperty("spring.datasource.password", ""))
                .driverClassName(env.getProperty("spring.datasource.driver-class-name", "org.h2.Driver"))
                .build();
    }
}
