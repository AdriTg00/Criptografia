import server.UserStore;
import server.MessageStore;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/*
=========================================================
SERVERMAIN
=========================================================

Esta clase:

- Arranca el servidor.
- Abre un puerto.
- Espera clientes.
- Crea un hilo ClientHandler por cada cliente.

*/

public class ServerMain {

    public static final int PORT = 15000;

    public static void main(String[] args) {

        System.out.println("=== SecureDrop Server v1 (INSEGURA) ===");
        System.out.println("Puerto: " + PORT);

        UserStore userStore = new UserStore("users.txt");
        MessageStore messageStore = new MessageStore("data");

        try (
                // =====================================================
                // TODO 1:
                // Cambiar ServerSocket por SSLServerSocket.
                //
                // Esto activará comunicación cifrada (TLS).
                // =====================================================
                ServerSocket serverSocket = new ServerSocket(PORT)
        ) {

            while (true) {

                Socket client = serverSocket.accept();

                System.out.println("[+] Cliente conectado: "
                        + client.getRemoteSocketAddress());

                // =====================================================
                // TODO 2:
                // Se podría añadir:
                // - Timeout de conexión
                // - Registro en archivo log
                // =====================================================

                new Thread(
                        new server.ClientHandler(client, userStore, messageStore)
                ).start();
            }

        } catch (IOException e) {

            // =====================================================
            // TODO 3:
            // No mostrar detalles técnicos.
            // Mostrar solo mensaje genérico y guardar log.
            // =====================================================

            System.err.println("Error en el servidor: " + e);
            e.printStackTrace();
        }
    }
}
