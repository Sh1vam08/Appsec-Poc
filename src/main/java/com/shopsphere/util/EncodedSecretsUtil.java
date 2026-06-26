package com.shopsphere.util;

import java.util.Base64;

/**
 * BENCH-SECRET-031: Base64-encoded secrets
 * Tests: Entropy-based secret discovery, Secret-type classification
 *
 * Secrets are stored as Base64-encoded strings and decoded at runtime.
 * A scanner must detect that these are encoded credentials, not random data.
 */
public class EncodedSecretsUtil {

    // Base64-encoded AWS Access Key: AKIAIOSFODNN7EXAMPLE
    private static final String ENCODED_AWS_KEY = "QUtJQUlPU0ZPRE5ON0VYQU1QTEU=";

    // Base64-encoded AWS Secret Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    private static final String ENCODED_AWS_SECRET = "d0phbHJYVXRuRkVNSS9LN01ERU5HL2JQeFJmaUNZRVhBTVBMRUtFWQ==";

    // Base64-encoded GitHub token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12
    private static final String ENCODED_GITHUB_TOKEN = "Z2hwX0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmMTI=";

    // Base64-encoded database connection string
    private static final String ENCODED_DB_URL = "amRiYzpteXNxbDovL2FkbWluOlByMGR1Y3Rpb25QQHNzdzByZCFAbG9jYWxob3N0OjMzMDYvY3VzdG9tZXJz";

    public static String getAwsAccessKey() {
        return new String(Base64.getDecoder().decode(ENCODED_AWS_KEY));
    }

    public static String getAwsSecretKey() {
        return new String(Base64.getDecoder().decode(ENCODED_AWS_SECRET));
    }

    public static String getGithubToken() {
        return new String(Base64.getDecoder().decode(ENCODED_GITHUB_TOKEN));
    }

    public static String getDatabaseUrl() {
        return new String(Base64.getDecoder().decode(ENCODED_DB_URL));
    }
}
