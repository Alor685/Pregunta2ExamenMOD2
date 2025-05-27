/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package util;

/**
 *
 * @author Alor
 */
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class hash512 {

    /**
     * Genera el hash SHA-256 de una cadena de texto.
     * @param texto El texto a hashear.
     * @return Hash SHA-256 en formato hexadecimal.
     * @throws NoSuchAlgorithmException
     */
    public static String sha256(String texto) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(texto.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hashBytes);
    }

    // Convierte un arreglo de bytes a una cadena hexadecimal
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if(hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Ejemplo de uso
    public static void main(String[] args) {
        try {
            String texto = "123";
            String hash = sha256(texto);
            System.out.println("Texto: " + texto);
            System.out.println("SHA-256: " + hash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
