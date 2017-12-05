package PasswordCracker;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static PasswordCracker.PasswordCrackerConsts.*;
import java.util.Collections;
import java.util.List;
import java.util.ArrayList;

public class PasswordCrackerTask implements Runnable {

    int taskId;
    boolean isEarlyTermination;
    PasswordFuture passwordFuture;
    PasswordCrackerConsts consts;

    public PasswordCrackerTask(int taskId, boolean isEarlyTermination, PasswordCrackerConsts consts, PasswordFuture passwordFuture) {
        this.taskId = taskId;
        this.isEarlyTermination = isEarlyTermination;
        this.consts = consts;
        this.passwordFuture = passwordFuture;
    }

    @Override
    public void run() {
        long rangeBegin = taskId * consts.getPasswordSubRangeSize();
        long rangeEnd = (taskId + 1) * consts.getPasswordSubRangeSize();
        String passwordOrNull = findPasswordInRange(rangeBegin, rangeEnd, consts.getEncryptedPassword());
        if(passwordOrNull != null) {
            passwordFuture.set(passwordOrNull);
        }
    }
    
    public String findPasswordInRange(long rangeBegin, long rangeEnd, String encryptedPassword) {
        MessageDigest msg = getMessageDigest();
        int[] numArrayInBase36 = new int[consts.passwordLength];
        transformDecToBase36(rangeBegin, numArrayInBase36);      
        for(long i = rangeBegin; i < rangeEnd; i++){
            if(isEarlyTermination && passwordFuture.isDone()) {
                return null;
            }
            String str = transformIntToStr(numArrayInBase36);             
            String md = encrypt(str, msg);
            if(md.equals(encryptedPassword)) {
                return str;
            }
            getNextCandidate(numArrayInBase36);
        }   
        return null;
    }

    /* ###	transformDecToBase36  ###
     * The transformDecToBase36 transforms decimal into numArray that is base 36 number system
    */
    private static void transformDecToBase36(long numInDec, int[] numArrayInBase36) {
        List<Integer> list = new ArrayList<>();
        do {
            list.add((int)(numInDec % 36));
            numInDec /= 36;
        } while (numInDec != 0); 
        Collections.reverse(list);
        for(int i = 0; i < list.size(); i++){
            numArrayInBase36[i] = list.get(i);
        }
    }

    /*
     * The getNextCandidate update the possible password represented by 36 base system
    */
    private static void getNextCandidate(int[] candidateChars) {
        candidateChars[candidateChars.length - 1]++;
        for(int i = candidateChars.length - 1; i > 0; i--){
            if(candidateChars[i] > 35) {
                candidateChars[i] = 0;
                candidateChars[i - 1] ++;
            }
            else break;
        } 
    }

    /*
     * We assume that each character can be represented to a number : 0 (0) , 1 (1), 2 (2) ... a (10), b (11), c (12), ... x (33), y (34), z (35)
     * The transformIntToStr transforms int-array into string (numbers and lower-case alphabets)
     * int array is password represented by base-36 system
     * return : password String
     *
     * For example, if you write the code like this,
     *     int[] pwdBase36 = {10, 11, 12, 13, 0, 1, 9, 2};
     *     String password = transfromIntoStr(pwdBase36);
     *     System.out.println(password);
     *     output is abcd0192.
     *
    */
    private static String transformIntToStr(int[] chars) {
        char[] password = new char[chars.length];
        for (int i = 0; i < password.length; i++) {
            password[i] = PASSWORD_CHARS.charAt(chars[i]);
        }
        return new String(password);
    }

    public static MessageDigest getMessageDigest() {
        try {
            return MessageDigest.getInstance("MD5");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Cannot use MD5 Library:" + e.getMessage());
        }
    }

    public static String encrypt(String password, MessageDigest messageDigest) {
        messageDigest.update(password.getBytes());
        byte[] hashedValue = messageDigest.digest();
        return byteToHexString(hashedValue);
    }

    public static String byteToHexString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xFF & bytes[i]);
            if (hex.length() == 1) {
                builder.append('0');
            }
            builder.append(hex);
        }
        return builder.toString();
    }
}
