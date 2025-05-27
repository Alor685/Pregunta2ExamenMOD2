/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package util;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class DesUtil {

    /**
     * Descifra un texto cifrado con TripleDES (DESede) en modo ECB con padding PKCS5.
     * @param encryptedText Texto cifrado en base64
     * @param secretKey Clave secreta de 24 caracteres
     * @return Texto descifrado en claro
     * @throws Exception Si ocurre algún error
     */
    public static String decrypt(String encryptedText, String secretKey) throws Exception {
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);

        if (keyBytes.length != 24) {
            throw new IllegalArgumentException("La clave debe tener exactamente 24 caracteres");
        }

        SecretKey key = new SecretKeySpec(keyBytes, "DESede");
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

}
