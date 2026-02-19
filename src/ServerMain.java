import server.SecurityPolicy;
import server.UserStore;
import server.MessageStore;
import crypto.RSAUtil;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/*
=========================================================
SERVERMAIN
=========================================================

Esta clase:

- Arranca el servidor.
- Genera el par de claves RSA.
- Abre un puerto.
- Espera clientes.
- Crea un hilo ClientHandler por cada cliente.

*/

public class ServerMain {

    public static final int PORT = 15000;

    public static void main(String[] args) {

        // 🔐 Inicializar claves RSA del servidor
        try {
            RSAUtil.init();
            System.out.println("[OK] Claves RSA generadas correctamente");
        } catch (Exception e) {
            System.err.println("Error inicializando RSA");
            e.printStackTrace();
            return;
        }

        SecurityPolicy securityPolicy = new SecurityPolicy();

        System.out.println("=== SecureDrop Server v1 (INSEGURA) ===");
        System.out.println("Puerto: " + PORT);

        UserStore userStore = new UserStore("users.txt");
        MessageStore messageStore = new MessageStore("data");

        try {
                // ANTES
                //ServerSocket serverSocket = new ServerSocket(PORT)
                // DESPUES
                System.setProperty("javax.net.ssl.keyStore", "ssl/servidor_keystore.jks");
                System.setProperty("javax.net.ssl.keyStorePassword", "123456");

                SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

                SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(15000);

                System.out.println("Servidor TLS iniciado...");
            while (true) {

                Socket client = serverSocket.accept();

                System.out.println("[+] Cliente conectado: "
                        + client.getRemoteSocketAddress());

                new Thread(
                        new server.ClientHandler(
                                client,
                                userStore,
                                messageStore,
                                securityPolicy
                        )
                ).start();
            }

        } catch (IOException e) {

            System.err.println("Error en el servidor");
            e.printStackTrace();
        }
    }
}
