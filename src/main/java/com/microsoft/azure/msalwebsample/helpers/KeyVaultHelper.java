package com.microsoft.azure.msalwebsample.helpers;

import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.microsoft.azure.msalwebsample.beans.BasicConfiguration;
import com.microsoft.azure.msalwebsample.beans.KeyVaultConfiguration;
import com.sun.org.slf4j.internal.Logger;
import com.sun.org.slf4j.internal.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class KeyVaultHelper {

    private static final Logger logger = LoggerFactory.getLogger(KeyVaultHelper.class);
    private SecretClient secretClient = null;
    private KeyClient keyClient = null;

    @Autowired
    KeyVaultConfiguration keyVaultConfig;

    @Autowired
    BasicConfiguration basicConfiguration;

    public KeyVaultHelper() {
    }

    private void createSecretClient(){
        String keyVaultName = keyVaultConfig.getName();
        String keyVaultUri = "https://" + keyVaultName + ".vault.azure.net";

        secretClient = new SecretClientBuilder()
                .vaultUrl(keyVaultUri)
                .credential(createCredential())
                .buildClient();
    }

    private void createKeyClient(){
        String keyVaultName = keyVaultConfig.getName();
        String keyVaultUri = "https://" + keyVaultName + ".vault.azure.net";

        this.keyClient = new KeyClientBuilder()
                .vaultUrl(keyVaultUri)
                .credential(createCredential())
                .buildClient();
    }

    private SecretClient getSecretClient(){
        if(this.secretClient == null){
            System.out.println("key vault secret client not found.");
            createSecretClient();
        }

        return secretClient;
    }

    private KeyClient getKeyClient(){
        if (this.keyClient == null){
            System.out.println("key vault key client not found.");
            createKeyClient();
        }
        return keyClient;
    }

    public KeyVaultSecret getSecret(String secretName){
        SecretClient getClient = getSecretClient();
        return getClient.getSecret(secretName);
    }

    public KeyVaultKey getKey(String keyName){
        KeyClient getClient = getKeyClient();
        return getClient.getKey(keyName);
    }

    private ClientSecretCredential createCredential(){
        return new ClientSecretCredentialBuilder()
                .clientId(basicConfiguration.getClientId())
                .clientSecret(basicConfiguration.getSecretKey())
                .tenantId(basicConfiguration.getTenantId())
                .build();
    }


}
