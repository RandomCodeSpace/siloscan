package internal.billing;

public final class Client {
    private static final String TWILIO_API_KEY = "{{TWILIO_0_180}}";
    private static final String AZURE_CLIENT_SECRET = "{{AZURE_0_181}}";
    private static final String GCP_API_KEY = "{{GCPKEY_0_182}}";
    private static final String SERVICE_PASSWORD = "{{PWA_16_183}}";
    private static final String SERVICE_TOKEN = "{{B64_40_184}}";
    private static final String KEYSTORE_PASSWORD = "{{PWP_20_185}}";
    private static final String AUTHORIZATION = "Bearer {{B64URL_43_186}}";
    private static final String BASIC_AUTHORIZATION = "Basic {{B64_44_187}}";
    private static final String JDBC_URL = "jdbc:postgresql://billing:{{PWA_20_188}}@db.internal:5432/billing";

    private static final String PASSWORD_PROPERTY = "spring.datasource.password";
    private static final String PASSWORD_FROM_ENV = System.getenv("SERVICE_PASSWORD");
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String DEFAULT_PASSWORD = "changeit";
    private static final String KEYSTORE_PATH = "/etc/billing/keystore.p12";
    private static final String TOKEN_PATTERN = "^[A-Za-z0-9_-]{20,64}$";
}
