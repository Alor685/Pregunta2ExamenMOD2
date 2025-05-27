/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/JSP_Servlet/Servlet.java to edit this template
 */
package servlet;

import dao.ClienteJpaController;
import dto.Cliente;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import util.hash512;
/**
 *
 * @author Alor
 */
@WebServlet(name = "LoginServlet", urlPatterns = {"/loginservlet"})
public class LoginServlet extends HttpServlet {

    private static final String claveSecreta = "mi-clave-secreta123"; // 16 bytes para AES, ajusta si usas DES

   private ClienteJpaController clienteDAO = new ClienteJpaController();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {

        String usuario = request.getParameter("encryptedLogin");
        String encryptedPass = request.getParameter("encryptedPass");
        String salt = request.getParameter("salt");

        if (usuario == null || encryptedPass == null || salt == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Faltan parámetros");
            return;
        }

        try {
            // Descifrar la contraseña con TripleDES
            String contrasenaConSalt = decryptTripleDES(encryptedPass, claveSecreta);

            if (!contrasenaConSalt.startsWith(salt)) {
                response.getWriter().println("Error: Salt no coincide");
                return;
            }

            String contrasenaOriginal = contrasenaConSalt.substring(salt.length());

            // Hashear con SHA-512
            String contrasenaHasheada = hash512.sha256(contrasenaOriginal);

            // Crear cliente con usuario y pass hasheada
            Cliente clienteParaValidar = new Cliente();
            clienteParaValidar.setLogiClie(usuario);
            clienteParaValidar.setPassClie(contrasenaHasheada);

            // Validar en BD
            Cliente clienteValidado = clienteDAO.validar(clienteParaValidar);

            if (clienteValidado != null) {
                response.getWriter().println("Login exitoso para usuario: " + usuario);
            } else {
                response.getWriter().println("Usuario o contraseña incorrectos");
            }

        } catch (Exception e) {
            e.printStackTrace();
            response.getWriter().println("Error al procesar: " + e.getMessage());
        }
    }

    private String decryptTripleDES(String encryptedText, String secretKey) throws Exception {
        // Configurar clave y cifrador TripleDES
        byte[] keyBytes = secretKey.getBytes("UTF-8");

        // En TripleDES la clave debe ser de 24 bytes, ajusta o rellena si es necesario
        byte[] keyBytes24 = new byte[24];
        System.arraycopy(keyBytes, 0, keyBytes24, 0, Math.min(keyBytes.length, 24));

        SecretKeySpec key = new SecretKeySpec(keyBytes24, "DESede");

        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);

        byte[] decryptedBytes = cipher.doFinal(decodedBytes);

        return new String(decryptedBytes, "UTF-8");
    }
}
