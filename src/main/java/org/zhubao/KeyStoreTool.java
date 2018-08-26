package org.zhubao;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class KeyStoreTool {

    public PublicKey getPublicKey(String keyStoreAlias,String keyStorePass, String keyStoreFile) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        InputStream fin= KeyStoreTool.class.getClassLoader().getResourceAsStream(keyStoreFile);
        ks.load(fin, keyStorePass.toCharArray());
        Certificate cert = ks.getCertificate(keyStoreAlias);
        PublicKey pubkey = cert.getPublicKey();
        return pubkey;
    }
    
    private Map<String, Object> generateJWK(PublicKey publicKey){
        RSAPublicKey rsa = (RSAPublicKey) publicKey;
        Map<String, Object> values = new HashMap<>();
        values.put("kty", rsa.getAlgorithm()); 
        values.put("kid", "wso2carbon");
        values.put("n", Base64.getUrlEncoder().encodeToString(rsa.getModulus().toString().getBytes()));
        values.put("e", Base64.getUrlEncoder().encodeToString(rsa.getPublicExponent().toString().getBytes()));
        values.put("alg", "RS256");
        values.put("use", "sig");
        return values;
    }
    
    public static void main(String[] args) throws Exception {
        KeyStoreTool keyStoreTool = new KeyStoreTool();
        PublicKey publicKey = keyStoreTool.getPublicKey("wso2carbon", "wso2carbon", "wso2carbon.jks");
        Map<String, Object> jwkSets = keyStoreTool.generateJWK(publicKey);
        System.out.println(jwkSets);
    }
}
