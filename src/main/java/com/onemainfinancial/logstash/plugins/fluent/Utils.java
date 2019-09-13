package com.onemainfinancial.logstash.plugins.fluent;

import org.msgpack.type.Value;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

class Utils {
    private static final String MD_ALGORITHM = "SHA-512";

    private Utils() {
        //no-op
    }

    static String getHexDigest(byte[]... updates) {
        try {
            MessageDigest md = MessageDigest.getInstance(MD_ALGORITHM);
            StringBuilder hexString = new StringBuilder();
            for (byte[] b : updates) {
                md.update(b);
            }
            for (byte b : md.digest()) {
                String hex = Integer.toHexString(0xFF & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }

    static String asString(Value value) {
        char[] chars = value.toString().toCharArray();
        int l = chars.length;
        if(l == 0){
            return "";
        }
        StringBuilder b = new StringBuilder();
        int s = 0;
        boolean escaped = false;
        if (chars[0] == '"') {
            s = 1;
            l = l - 1;
        }
        for (int i = s; i < l; i++) {
            char x = chars[i];
            if (!escaped && x == '\\') {
                escaped = true;
                continue;
            }
            escaped = false;
            b.append(x);
        }
        return b.toString();
    }

    static byte[] generateSalt() {
        byte[] b = new byte[16];
        new Random().nextBytes(b);
        return b;
    }
}
