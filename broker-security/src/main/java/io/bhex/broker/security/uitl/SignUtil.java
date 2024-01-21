package io.bhex.broker.security.uitl;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import io.jsonwebtoken.impl.TextCodec;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class SignUtil {

    /**
     * 加密算法
     */
    private static final String ALGORITHM = "AES";

    /**
     * 加密算法/加密模式/填充类型
     * 本例采用AES加密，ECB加密模式，PKCS5Padding填充
     */
    private static final String CIPHER_MODE = "AES/ECB/PKCS5Padding";

    public static String encryptData(String key, String data) throws Exception {
        return encryptData(key, data.getBytes(Charsets.UTF_8));
    }

    public static String encryptData(String key, byte[] data) throws Exception {
        byte[] keyBytes = Hashing.sha256().hashString(key, Charsets.UTF_8).asBytes();
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] cipherTextBytes = cipher.doFinal(data);
        return TextCodec.BASE64.encode(cipherTextBytes);
    }

    public static String decryptData(String key, String data) throws Exception {
        return decryptData(key, TextCodec.BASE64.decode(data));
    }

    public static String decryptData(String key, byte[] data) throws Exception {
        byte[] keyBytes = Hashing.sha256().hashString(key, Charsets.UTF_8).asBytes();
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] cipherTextBytes = cipher.doFinal(data);
        return new String(cipherTextBytes, Charsets.UTF_8);
    }

}
