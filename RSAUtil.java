package com.cats.common.core;

import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import com.google.common.base.Splitter;
import com.google.common.collect.Maps;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.util.StringUtils;

import javax.crypto.Cipher;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

@Slf4j
public class RSAUtil {
    public static final String RSA_ALGORITHM = "RSA";
    public static final String UTF8_STR = "UTF-8";
    public static final Integer KEY_SIZE = 1024;
    public static final String TIME_STAMP = "timestamp";
    public static final String JOIN_CHAR_1 = "=";
    public static final String JOIN_CHAR_2 = "&";
    public static final String JOIN_CHAR_3 = ",";

    /**
     * 随机生成密钥对
     *
     * @throws NoSuchAlgorithmException
     */
    public static List<String> genKeyPair() {
        List<String> result = new ArrayList<>();
        try {
            // KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            // 初始化密钥对生成器，密钥大小为96-1024位
            keyPairGen.initialize(KEY_SIZE, new SecureRandom());
            // 生成一个密钥对，保存在keyPair中
            KeyPair keyPair = keyPairGen.generateKeyPair();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();   // 得到私钥 Base64.decodeBase64
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();  // 得到公钥
            String publicKeyString = new String(Base64.encodeBase64(publicKey.getEncoded()));
            // 得到私钥字符串
            String privateKeyString = new String(Base64.encodeBase64((privateKey.getEncoded())));
            // 将公钥和私钥保存到
            result.add(publicKeyString);
            result.add(privateKeyString);
        } catch (NoSuchAlgorithmException e) {
            log.error("RSAUtil genKeyPair ", e);
        }
        return result;
    }

    /**
     * RSA公钥加密
     *
     * @param str       加密字符串
     * @param publicKey 公钥
     * @return 密文
     * @throws Exception 加密过程中的异常信息
     */
    public static String encrypt(String str, String publicKey) throws Exception {
        String outStr = null;
        try {
            //base64编码的公钥
            byte[] decoded = Base64.decodeBase64(publicKey);
            RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance(RSA_ALGORITHM).generatePublic(new X509EncodedKeySpec(decoded));
            //RSA加密
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            outStr = Base64.encodeBase64String(cipher.doFinal(str.getBytes(UTF8_STR)));
        } catch (Exception e) {
            log.error("RSAUtil encrypt ", e);
        }
        return outStr;
    }

    /**
     * RSA加密(私钥)
     *
     * @param str        加密字符串
     * @param privateKey 私钥
     * @return 密文
     * @throws Exception 加密过程中的异常信息
     */
    public static String encryptByPrivateKey(String str, String privateKey) throws Exception {
        String outStr = null;
        try {
            //base64编码的公钥
            byte[] decoded = Base64.decodeBase64(privateKey);
            RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance(RSA_ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(decoded));
            //RSA加密
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, priKey);
            outStr = Base64.encodeBase64String(cipher.doFinal(str.getBytes(UTF8_STR)));
        } catch (Exception e) {
            log.error("RSAUtil encryptByPrivateKey ", e);
        }
        return outStr;
    }

    /**
     * RSA解密(公钥)
     *
     * @param str       加密字符串
     * @param publicKey 公钥
     * @return 铭文
     * @throws Exception 解密过程中的异常信息
     */
    public static String decryptByPublicKey(String str, String publicKey) {
        String outStr = null;
        try {
            //64位解码加密后的字符串
            byte[] inputByte = Base64.decodeBase64(str.getBytes(StandardCharsets.UTF_8));
            //base64编码的私钥
            byte[] decoded = Base64.decodeBase64(publicKey);
            RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance(RSA_ALGORITHM).generatePublic(new X509EncodedKeySpec(decoded));
            //RSA解密
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, pubKey);
            outStr = new String(cipher.doFinal(inputByte));
        } catch (Exception e) {
            log.error("RSAUtil decryptByPublicKey ", e);
        }
        return outStr;
    }

    /**
     * RSA私钥解密(支持超长文本)
     *
     * @param str       加密字符串
     * @param publicKey 私钥
     * @return 铭文
     * @throws Exception 解密过程中的异常信息
     */
    public static String decrypt4LongTextByPublicKey(String str, String publicKey) {
        try {
            if (StringUtils.isEmpty(str)) {
                return null;
            }
            StringBuilder sb = new StringBuilder();
            String[] tempStr = str.split(JOIN_CHAR_3);
            for (String s : tempStr) {
                if (StringUtils.isEmpty(s)) {
                    return s;
                }
                String temp = decryptByPublicKey(s, publicKey);
                if (StringUtils.isEmpty(temp)) {
                    return temp;
                }
                sb.append(temp);
            }
            return URLDecoder.decode(sb.toString(), "UTF-8");
        } catch (Exception e) {
            System.out.println("decrypt4LongTextByPublicKey解密出现异常");
            return null;
        }
    }

    /**
     * 数据加密+签名(私钥)
     *
     * @param params     params
     * @param timestamp  timestamp
     * @param privateKey privateKey
     * @return String
     * @throws Exception
     */
    public static String encryptByPrivateKey(Map<String, Object> params, String timestamp, String privateKey) throws Exception {
        StringBuilder sb = new StringBuilder();
        Map<String, Object> sortParams = new TreeMap<>(params);
        sortParams.forEach((key, value) -> {
            if (!StringUtils.isEmpty(value)) {
                sb.append(key).append("=").append(value).append("&");
            }
        });
        String sortedBody = sb.substring(0, sb.length() - 1),
                salt = "timestamp=" + timestamp,
                signatureBeforeMD5 = salt + "&" + sortedBody;
        String signature = DigestUtils.md5Hex(signatureBeforeMD5).toUpperCase();
        sortParams.put("signature", signature);
        String toJson = JSONUtil.toJsonStr(sortParams);
        log.info("sortedBody={}，salt={}，signatureBeforeMD5={}，signature={}，toJson={}", sortedBody, salt, signatureBeforeMD5, signature, toJson);
        Iterable<String> chunks = Splitter.fixedLength(100).split(URLEncoder.encode(toJson, "UTF-8"));
        Iterator<String> iterator = chunks.iterator();
        StringBuilder sbEncryption = new StringBuilder();
        while (iterator.hasNext()) {
            String encrypt = encryptByPrivateKey(iterator.next(), privateKey);
            sbEncryption.append(encrypt).append(",");
        }
        Map<String, String> bodyData = Maps.newHashMap();
        bodyData.put("data", sbEncryption.substring(0, sbEncryption.length() - 1));
        return JSONUtil.toJsonStr(bodyData);
    }


    /**
     * RSA私钥解密
     *
     * @param str        加密字符串
     * @param privateKey 私钥
     * @return 铭文
     * @throws Exception 解密过程中的异常信息
     */
    public static String decrypt(String str, String privateKey) {
        String outStr = null;
        try {
            //64位解码加密后的字符串
            byte[] inputByte = Base64.decodeBase64(str.getBytes(UTF8_STR));
            //base64编码的私钥
            byte[] decoded = Base64.decodeBase64(privateKey);
            RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance(RSA_ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(decoded));
            //RSA解密
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, priKey);
            outStr = new String(cipher.doFinal(inputByte));
        } catch (Exception e) {
            log.error("RSAUtil decrypt ", e);
        }
        return outStr;
    }


    /**
     * RSA私钥解密(支持超长文本)
     *
     * @param str        加密字符串
     * @param privateKey 私钥
     * @return 铭文
     * @throws Exception 解密过程中的异常信息
     */
    public static String decrypt4LongText(String str, String privateKey) {
        try {
            if (StringUtils.isEmpty(str)) {
                return null;
            }
            StringBuilder sb = new StringBuilder();
            String[] tempStr = str.split(JOIN_CHAR_3);
            for (String s : tempStr) {
                if (StringUtils.isEmpty(s)) {
                    return s;
                }
                String temp = decrypt(s, privateKey);
                //LogUtil.info(CommonLogType.CODE_COMMON, "decrypt4LongText分段解密，原始密文>>>", s, "解密结果>>>", temp);
                if (StringUtils.isEmpty(temp)) {
                    return temp;
                }
                sb.append(temp);
            }
            return URLDecoder.decode(sb.toString(), "UTF-8");
        } catch (Exception e) {
            System.out.println("decrypt4LongText解密出现异常");
            return null;
        }
    }


    /**
     * 验证签名信息
     *
     * @param params  参数信息
     * @param signKey 加密之后key
     * @return 延签是否正常
     */
    public static boolean verifySign(Map<String, Object> params, String signKey) {
        try {
            if (StringUtils.isEmpty(params) || StringUtils.isEmpty(signKey)) {
                return Boolean.FALSE;
            }
            Object signValue = "";
            if (params.containsKey(signKey)) {
                signValue = params.remove(signKey);
            }
            if (StringUtils.isEmpty(signValue)) {
                return Boolean.FALSE;
            }
            StringBuilder sb = new StringBuilder().append(TIME_STAMP).append(JOIN_CHAR_1).append(params.get(TIME_STAMP));
            // 将参数以参数名的字典升序排序
            Map<String, Object> sortParams = new TreeMap<>(params);
            // 遍历排序的字典,并拼接"key=value"格式
            for (Map.Entry<String, Object> entry : sortParams.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();
                if (!StringUtils.isEmpty(value) && (value instanceof Number || value instanceof String))
                    sb.append(JOIN_CHAR_2).append(key).append(JOIN_CHAR_1).append(value);
            }
            String md5 = DigestUtils.md5Hex(sb.toString()).toUpperCase();
            System.out.println("verifySign验签参数");
            return signValue.equals(md5);
        } catch (Exception e) {
            System.out.println("verifySign验签出现问题");
            return false;
        }
    }



    /**
     * 对单词列表进行冒泡排序
     * 直接操作对象地址 无需返回
     *
     * @param words
     */
    private static void wordSort(ArrayList<String> words) {
        for (int i = words.size() - 1; i > 0; i--) {
            for (int j = 0; j < i; j++) {
                if (words.get(j).compareToIgnoreCase(words.get(j + 1)) > 0) {
                    String temp = words.get(j);
                    words.set(j, words.get(j + 1));
                    words.set(j + 1, temp);
                }
            }
        }
    }

    /**
     * jsonArray数据排序
     *
     * @param jsonArray
     * @return
     */
    private static JSONArray jsonArraySort(JSONArray jsonArray) {
        JSONArray sortArray = new JSONArray();
        for (Object o : jsonArray) {
            if (o.getClass().equals(JSONObject.class)) {
                sortArray.add(jsonSort((JSONObject)o));
            }
            sortArray.add(o);
        }
        return sortArray;
    }

    /**
     * json数据按key的ascii码排序
     *
     * @return
     */
    private static JSONObject jsonSort(JSONObject json) {
        ArrayList<String> aloneKeys = new ArrayList<>();
        for (String key : json.keySet()) {
            aloneKeys.add(key);
        }
        // 排序
        wordSort(aloneKeys);
        // 整理排序后的json
        JSONObject sortJson = new JSONObject(new LinkedHashMap<>());
        for (String key : aloneKeys) {
            Object value = json.get(key);
            if (value.getClass().equals(JSONObject.class)) {
                sortJson.put(key, jsonSort((JSONObject) value));
            } else if (value.getClass().equals(JSONArray.class)) {
                jsonArraySort((JSONArray) value);
            } else {
                sortJson.put(key, value);
            }
        }
        return sortJson;
    }

    /**
     * 数据加密+签名(私钥)
     *
     * @param params     params
     * @param timestamp  timestamp
     * @param privateKey privateKey
     * @return String
     * @throws Exception
     */
    public static String encryptByPrivateKeyV2(Map<String, Object> params, String timestamp, String privateKey) throws Exception {
        JSONObject sortParams = jsonSort(JSONUtil.parseObj(JSONUtil.toJsonStr(params)));
        StringBuilder sb = new StringBuilder();
        for (String key : sortParams.keySet()) {
            sb.append(key).append("=").append(sortParams.get(key)).append("&");
        }
        String sortedBody = sb.substring(0, sb.length() - 1),
                salt = "timestamp=" + timestamp,
                signatureBeforeMD5 = salt + "&" + sortedBody;
        String signature = DigestUtils.md5Hex(signatureBeforeMD5).toUpperCase();
        sortParams.put("signature", signature);
        String toJson = JSONUtil.toJsonStr(sortParams);
        log.info("sortedBody={}，salt={}，signatureBeforeMD5={}，signature={}，toJson={}", sortedBody, salt, signatureBeforeMD5, signature, toJson);
        Iterable<String> chunks = Splitter.fixedLength(100).split(URLEncoder.encode(toJson, "UTF-8"));
        Iterator<String> iterator = chunks.iterator();
        StringBuilder sbEncryption = new StringBuilder();
        while (iterator.hasNext()) {
            String encrypt = encryptByPrivateKey(iterator.next(), privateKey);
            sbEncryption.append(encrypt).append(",");
        }
        Map<String, String> bodyData = Maps.newHashMap();
        bodyData.put("data", sbEncryption.substring(0, sbEncryption.length() - 1));
        return JSONUtil.toJsonStr(bodyData);
    }

    public static void main(String[] args) throws Exception {
        //生成公钥和私钥
        List<String> list = genKeyPair();
        //加密字符串
        String message = "df723820";
        System.out.println("随机生成的公钥为:" + list.get(0));
        System.out.println("随机生成的私钥为:" + list.get(1));
        String messageEn = encrypt(message, list.get(0));
        System.out.println(message + "\t【公钥】加密后的字符串为:" + messageEn);
        String messageDe = decrypt(messageEn, list.get(1));
        System.out.println("【私钥】还原后的字符串为:" + messageDe);

        String messageEnV1 = encryptByPrivateKey(message, list.get(1));
        System.out.println(message + "\t【私钥】加密后的字符串为:" + messageEnV1);
        String messageDeV1 = decryptByPublicKey(messageEnV1, list.get(0));
        System.out.println("【公钥】还原后的字符串为:" + messageDeV1);


        String pk = "XXXXXX";
        System.out.printf(encrypt("{\"name\":\"XXXX\"}", pk));

        String priKey  = "XXXXXXX";
        System.out.println(decrypt4LongText("XXXXXX",priKey));

        System.out.println("还原后的字符串为:" + messageDe);
    }
}
