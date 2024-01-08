package cn.isekai.keycloak.federation.ucenter;

import org.jboss.logging.Logger;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class UCenterUtils {
    private static final Logger logger = Logger.getLogger(UCenterUtils.class);

    /**
     * 将字节数组转换为十六进制字符串
     *
     * @param input 输入的字节数组
     * @return 转换后的十六进制字符串
     */
    public static String bin2hex(byte[] input) {
        BigInteger bigInt = new BigInteger(1, input);
        StringBuilder hashText = new StringBuilder(bigInt.toString(16));
        while (hashText.length() < 32) {
            hashText.insert(0, "0");
        }
        return hashText.toString();
    }

    /**
     * 计算字符串的MD5哈希值
     *
     * @param input 输入字符串
     * @return 计算得到的MD5哈希值的十六进制字符串
     */
    public static String md5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(input.getBytes(StandardCharsets.UTF_8));
            return bin2hex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            logger.error("MD5 algorithm not found", e);
            return null;
        }
    }

    /**
     * 使用MD5哈希算法对密码和盐值进行哈希计算
     *
     * @param password 密码
     * @param salt     盐值
     * @return 哈希后的十六进制字符串
     */
    public static String makeHash(String password, String salt) {
        return md5(md5(password) + salt);
    }

    /**
     * 验证密码是否与哈希值匹配
     *
     * @param password 待验证的密码
     * @param hash     存储的哈希值
     * @param salt     盐值
     * @return 如果验证成功返回 true，否则返回 false
     */
    public static boolean validatePassword(String password, String hash, String salt) {
        return hash.equals(makeHash(password, salt));
    }

    /**
     * 生成随机的盐值
     *
     * @return 生成的盐值
     */
    public static String makeSalt() {
        String str = "0123456789abcdef";
        int strLen = str.length();
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            int number = random.nextInt(strLen);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }

    /**
     * 计算字符串的bcrypt哈希值
     * @param input 输入字符串
     * @return 计算得到的bcrypt哈希值的十六进制字符串
     */
    public static String bcrypt(String input) {
        return BCrypt.hashpw(input, BCrypt.gensalt());
    }

    /**
     * 验证密码是否与bcrypt哈希值匹配
     * @param password 待验证的密码
     * @param hash 存储的bcrypt哈希值
     * @return 如果验证成功返回 true，否则返回 false
     */
    public static boolean validatePassword(String password, String hash) {
        return BCrypt.checkpw(password, hash);
    }

}
