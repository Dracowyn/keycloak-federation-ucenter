package cn.isekai.keycloak.federation.ucenter;

import cn.isekai.keycloak.federation.ucenter.model.UserData;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Random;

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

    public static String makeHash(String password, String salt){
        return md5(md5(password) + salt);
    }

    public static boolean validatePassword(String password, String hash, String salt){
        return hash.equals(makeHash(password, salt));
    }

    public static String makeSalt(){
        String str = "0123456789abcdef";
        int strLen = str.length();
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < 6; i ++){
            int number = random.nextInt(strLen);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }
}
