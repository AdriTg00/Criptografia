package server;

import protocol.Protocol;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static java.lang.System.out;

/*
=========================================================
CLIENTHANDLER
=========================================================

Esta clase atiende a UN cliente.

Lee lo que escribe.
Decide qué comando es.
Ejecuta la acción.
Devuelve respuesta.

AQUÍ ES DONDE HAY QUE APLICAR LA SEGURIDAD.
*/

public class ClientHandler implements Runnable {

    private final Socket socket;
    private final UserStore userStore;
    private final MessageStore messageStore;
    private final SecurityPolicy securityPolicy;

    public ClientHandler(Socket socket, UserStore userStore, MessageStore messageStore, SecurityPolicy securityPolicy) {
        this.socket = socket;
        this.userStore = userStore;
        this.messageStore = messageStore;
        this.securityPolicy = securityPolicy;
    }

    private UserStore.User sessionUser = null;


    @Override
    public void run() {

        try (
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                PrintWriter out = new PrintWriter(
                        new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true)
        ) {

            out.println(Protocol.OK + " Bienvenido a SecureDrop v1");

            String line;

            while ((line = in.readLine()) != null) {

                if (line.length() > 500) {
                    out.println(Protocol.ERR + " Linea demasiado larga");
                    continue;
                }


                line = line.trim();
                if (line.isEmpty()) continue;

                String cmd;
                String rest = "";

                int firstSpace = line.indexOf(' ');
                if (firstSpace == -1) {
                    cmd = line.toUpperCase();
                } else {
                    cmd = line.substring(0, firstSpace).toUpperCase();
                    rest = line.substring(firstSpace + 1);
                }

                switch (cmd) {

                    case "LOGIN":
                        handleLogin(rest, out);
                        break;

                    case "SEND":
                        requireAuth(out);
                        if (sessionUser != null) handleSend(rest, out);
                        break;

                    case "LIST":
                        requireAuth(out);
                        if (sessionUser != null) handleListMine(out);
                        break;

                    case "LIST_ALL":
                        requireAuth(out);
                        if (sessionUser != null) handleListAll(out);
                        break;

                    case "QUIT":
                        out.println(Protocol.OK + " Bye");
                        return;

                    default:
                        out.println(Protocol.ERR + " Comando desconocido");
                }
            }

        } catch (Exception e) {
            out.println(Protocol.ERR + " Error interno");
            logError("Error en handler para usuario " +
                    (sessionUser != null ? sessionUser.username : "<no autenticado>"), e);

            System.err.println("Error en handler: " + e);
            e.printStackTrace();

        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    private void logError(String msg, Exception e) {
        try (FileWriter fw = new FileWriter("server-errors.log", true);
             PrintWriter pw = new PrintWriter(fw)) {
            pw.println("[" + new java.util.Date() + "] " + msg);
            e.printStackTrace(pw);
        } catch (IOException ignored) {}
    }


    private void handleLogin(String rest, PrintWriter out) {


        // =====================================================
        // TODO 3: Mejorar autenticación
        //
        // Ahora mismo la contraseña se compara directamente
        // y en users.txt está guardada la contraseña REAL.
        // Eso es inseguro.
        //
        // En la versión segura hay que:
        //
        // 1) NO guardar la contraseña real.
        // 2) Guardar HASH + SALT de la contraseña.
        // 3) Cuando el usuario escriba su contraseña,
        //    calcular su HASH y comparar HASH con HASH.
        // 4) Limitar intentos fallidos y bloquear usuario.
        //
        // Es decir:
        //    hash(passwordEscrita + salt) == hashGuardado
        //
        // NO volver a comparar contraseñas en texto normal.
        // =====================================================

        String[] parts = rest.split(" ", 2);
        if (parts.length < 2) {
            out.println(Protocol.ERR + " Uso: LOGIN <user> <pass>");
            return;
        }

        String user = parts[0].trim();
        String pass = parts[1].trim();

        // 1) Comprobar si el usuario está bloqueado
        if (securityPolicy.isBlocked(user)) {
            out.println(Protocol.ERR + " Usuario bloqueado temporalmente por intentos fallidos");
            return;
        }

        Optional<UserStore.User> u = userStore.authenticate(user, pass);

        if (u.isPresent()) {
            sessionUser = u.get();
            out.println(Protocol.OK + " Autenticado como "
                    + sessionUser.username + " (" + sessionUser.role + ")");
        } else {
            securityPolicy.registerFailure(user);
            out.println(Protocol.ERR + " Credenciales incorrectas");
        }
    }

    private void handleSend(String message, PrintWriter out) {

        if (message == null || message.trim().isEmpty()) {
            out.println(Protocol.ERR + " Uso: SEND <mensaje>");
            return;
        }

        try {

            String trimmed = message == null ? "" : message.trim();
            if (trimmed.isEmpty()) {
                out.println(Protocol.ERR + " Uso: SEND <mensaje>");
                return;
            }
            if (trimmed.length() > 1000) {
                out.println(Protocol.ERR + " Mensaje demasiado largo");
                return;
            }


            messageStore.storeMessage(sessionUser.username, message);

            out.println(Protocol.OK + " Mensaje almacenado");

        } catch (Exception e) {
            out.println(Protocol.ERR + " Error guardando mensaje");
        }
    }

    private void handleListMine(PrintWriter out) {

        try {

            List<File> files =
                    messageStore.listMessagesForUser(sessionUser.username);

            out.println(Protocol.OK + " Mensajes de "
                    + sessionUser.username + " (" + files.size() + ")");

            for (File f : files) {

                // =====================================================
                // TODO 5:
                // Cuando los mensajes estén cifrados,
                // aquí habrá que DESCIFRARLOS antes de mostrarlos.
                // =====================================================

                out.println("--- " + f.getName() + " ---");
                out.println(messageStore.readFile(f));
            }

            out.println(Protocol.END);

        } catch (Exception e) {
            out.println(Protocol.ERR + " Error listando");
            out.println(Protocol.END);
        }
    }

    private void handleListAll(PrintWriter out) {

        // =====================================================
        // TODO 6:
        // Asegurarse de que SOLO ADMIN pueda entrar aquí.
        // Revisar que nadie pueda saltarse esta restricción.
        // =====================================================

        if (sessionUser.role != UserStore.Role.ADMIN) {
            out.println(Protocol.ERR + " Acceso denegado (solo ADMIN)");
            out.println(Protocol.END);
            return;
        }

        try {

            List<File> files = messageStore.listAllMessages();

            out.println(Protocol.OK + " TODOS los mensajes (" + files.size() + ")");

            for (File f : files) {
                out.println("--- " + f.getName() + " ---");
                out.println(messageStore.readFile(f));
            }

            out.println(Protocol.END);

        } catch (Exception e) {
            out.println(Protocol.ERR + " Error listando");
            out.println(Protocol.END);
        }
    }

    private void requireAuth(PrintWriter out) {

        if (sessionUser == null) {
            out.println(Protocol.ERR + " Debes autenticarte primero (LOGIN)");
        }
    }
}
