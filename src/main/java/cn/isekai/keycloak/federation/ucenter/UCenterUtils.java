package cn.isekai.keycloak.federation.ucenter;

import cn.isekai.keycloak.federation.ucenter.model.UserData;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class UCenterUtils {
    public static String bin2hex(byte[] input){
        BigInteger bigInt = new BigInteger(1, input);
        StringBuilder hashText = new StringBuilder(bigInt.toString(16));
        while(hashText.length() < 32){
            hashText.insert(0, "0");
        }
        return hashText.toString();
    }

    public static String md5(String input){
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(input.getBytes(StandardCharsets.UTF_8));
            return bin2hex(md.digest());
        } catch(Exception e){
            return null;
        }
    }

    public static boolean validatePassword(String password, String hash, String salt){
        return hash.equals(md5(md5(password) + salt));
    }
}
