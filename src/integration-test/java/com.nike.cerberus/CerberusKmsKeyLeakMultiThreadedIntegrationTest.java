package com.nike.cerberus;

import com.amazonaws.regions.Region;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.EncryptResult;
import com.google.common.collect.ImmutableMap;
import com.google.inject.*;
import com.jayway.restassured.response.ValidatableResponse;
import com.nike.backstopper.handler.riposte.config.guice.BackstopperRiposteConfigGuiceModule;
import com.nike.cerberus.auth.connector.AuthConnector;
import com.nike.cerberus.aws.KmsClientFactory;
import com.nike.cerberus.dao.AwsIamRoleDao;
import com.nike.cerberus.record.AwsIamRoleRecord;
import com.nike.cerberus.server.config.CmsConfig;
import com.nike.cerberus.server.config.guice.*;
import com.nike.cerberus.service.ConfigService;
import com.nike.cerberus.service.EncryptionService;
import com.nike.cerberus.service.KmsService;
import com.nike.guice.typesafeconfig.TypesafeConfigPropertiesRegistrationGuiceModule;
import com.nike.riposte.server.config.ServerConfig;
import com.typesafe.config.Config;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;

import java.nio.ByteBuffer;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static com.jayway.restassured.RestAssured.given;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.*;
import static org.mockito.MockitoAnnotations.initMocks;

public class CerberusKmsKeyLeakMultiThreadedIntegrationTest {

    private static List<Module> moduleList = new LinkedList<>();

    private static KmsService kmsService;

    @Mock
    private EncryptionService encryptionService;

    @Mock
    private AuthConnector authConnector;

    @Mock
    private KmsClientFactory kmsClientFactory;

    @Mock
    private AWSKMSClient kmsClient;

    private static AwsIamRoleDao awsIamRoleDao;

    private TestServer testServer;

    class TestConfig extends CmsConfig {
        public TestConfig(Config appConfig) {
            super(appConfig, new TypesafeConfigPropertiesRegistrationGuiceModule(appConfig), Optional.of(moduleList));
        }
    }

    class TestServer extends Main {

        private final TestConfig config;

        public TestServer() {
            config = new TestConfig(ConfigService.getInstance().getAppConfigMergedWithCliGeneratedProperties());
        }

        @Override
        protected ServerConfig getServerConfig(Config appConfig) {
            return config;
        }
    }

    class MockSupplyingModule extends AbstractModule {
        @Override
        protected void configure() {
            bind(EncryptionService.class).toInstance(encryptionService);
            bind(AuthConnector.class).toInstance(authConnector);
            bind(KmsClientFactory.class).toInstance(kmsClientFactory);
        }

        @Provides
        @Singleton
        public KmsService kmsService() {
            List<Module> appGuiceModules = new ArrayList<>();
            appGuiceModules.add(new TypesafeConfigPropertiesRegistrationGuiceModule(ConfigService.getInstance().getAppConfigMergedWithCliGeneratedProperties()));
            appGuiceModules.addAll(Arrays.asList(
                    new CmsMyBatisModule(),
                    new BackstopperRiposteConfigGuiceModule(),
                    new CmsFlywayModule(),
                    new OneLoginGuiceModule(),
                    new MetricsGuiceModule(),
                    new CerberusBackstopperRiposteGuiceModule(),
                    new CmsGuiceModule(CmsConfig.configureObjectMapper())
            ));
            Injector injector = Guice.createInjector(appGuiceModules);
            KmsService kmsServiceActual = injector.getInstance(KmsService.class);

            kmsService = Mockito.spy(kmsServiceActual);
            return kmsService;
        }

        @Provides
        @Singleton
        public AwsIamRoleDao awsIamRoleDao() {

            List<Module> appGuiceModules = new ArrayList<>();
            appGuiceModules.add(new TypesafeConfigPropertiesRegistrationGuiceModule(ConfigService.getInstance().getAppConfigMergedWithCliGeneratedProperties()));
            appGuiceModules.add(new CmsMyBatisModule());
            Injector injector = Guice.createInjector(appGuiceModules);
            AwsIamRoleDao awsIamRoleDaoActual = injector.getInstance(AwsIamRoleDao.class);

            awsIamRoleDao = Mockito.spy(awsIamRoleDaoActual);
            return awsIamRoleDao;
        }
    }

    @Before
    public void before() throws Exception {
        initMocks(this);

        moduleList.add(new MockSupplyingModule());

        System.setProperty("@appId", "cms");
        System.setProperty("@environment", "local");
        String[] args = new String[0];
        testServer = new TestServer();
        testServer.launchServer(args);
    }

    @After
    public void after() {
        moduleList.clear();
    }

    @Test
    public void test_that_kms_service_provision_key_is_only_called_once_multi_threaded() throws Exception {
        String iamRoleArn = "arn:aws:iam::111111111:role/" + UUID.randomUUID().toString();
        awsIamRoleDao.createIamRole(new AwsIamRoleRecord()
                .setAwsIamRoleArn(iamRoleArn)
                .setId(UUID.randomUUID().toString())
                .setCreatedBy("CerberusKmsKeyLeakMultiThreadedIntegrationTest")
                .setCreatedTs(OffsetDateTime.now())
                .setLastUpdatedBy("CerberusKmsKeyLeakMultiThreadedIntegrationTest")
                .setLastUpdatedTs(OffsetDateTime.now())
        );

        // Stub kms key provisioning
        doReturn("arn:aws:kms:us-west-2:111111111:key/" + UUID.randomUUID().toString())
                .when(kmsService).createKmsKeyInAws(anyString(), anyString(), anyString());

        // Stub in a mock kms client, when the factory creates clients for regions
        when(kmsClientFactory.getClient(any(Region.class))).thenReturn(kmsClient);

        // stub kms when ecrypt is called
        when(kmsClient.encrypt(any())).thenReturn(new EncryptResult()
                .withCiphertextBlob(ByteBuffer.wrap("muh secret blob".getBytes())));

        ExecutorService executor = Executors.newFixedThreadPool(20);

        for (int i = 0; i < 20; i++) {
            executor.execute(() -> {
                ValidatableResponse response = given().body(ImmutableMap.of(
                        "iam_principal_arn", iamRoleArn,
                        "region", "us-west-2"
                )).post("http://localhost:8080/v2/auth/iam-principal").then();
                response.statusCode(200);
            });
        }

        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.SECONDS);

        verify(kmsService, times(1)).provisionKmsKey(anyString(), anyString(), anyString(), anyString(), any());
    }

}
