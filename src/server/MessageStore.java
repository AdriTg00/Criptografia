package server;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

/*
MessageStore se encarga de:

- Guardar mensajes en la carpeta data/
- Listar mensajes
- Leer archivos

Actualmente guarda todo en texto plano (inseguro).
Aquí es donde se aplicará el cifrado AES.
*/

public class MessageStore {

    private final File baseDir;
    private final SimpleDateFormat fmt =
            new SimpleDateFormat("yyyyMMdd_HHmmss");

    public MessageStore(String dir) {
        this.baseDir = new File(dir);

        // Si la carpeta no existe, la crea automáticamente
        if (!baseDir.exists()) baseDir.mkdirs();
    }

    public File storeMessage(String username, String message)
            throws IOException {

        String ts = fmt.format(new Date());
        File f = new File(baseDir,
                username + "_" + ts + ".txt");

        try (Writer w = new OutputStreamWriter(
                new FileOutputStream(f),
                StandardCharsets.UTF_8)) {

            w.write("From: " + username + "\n");
            w.write("Date: " + new Date() + "\n");
            w.write("Message:\n");

            // =====================================================
            // TODO 1: CIFRAR MENSAJE
            //
            // Ahora mismo el mensaje se guarda en texto normal.
            //
            // En la versión segura:
            //
            // 1) Generar clave AES.
            // 2) Cifrar el mensaje.
            // 3) Guardar el mensaje cifrado en el archivo.
            //
            // El archivo NO debe poder leerse directamente.
            // =====================================================

            w.write(message + "\n");
        }

        return f;
    }

    public List<File> listMessagesForUser(String username) {

        File[] files = baseDir.listFiles(
                (d, name) ->
                        name.startsWith(username + "_")
                                && name.endsWith(".txt"));

        if (files == null)
            return Collections.emptyList();

        Arrays.sort(files,
                Comparator.comparing(File::getName)
                        .reversed());

        return Arrays.asList(files);
    }

    public List<File> listAllMessages() {

        File[] files = baseDir.listFiles(
                (d, name) -> name.endsWith(".txt"));

        if (files == null)
            return Collections.emptyList();

        Arrays.sort(files,
                Comparator.comparing(File::getName)
                        .reversed());

        return Arrays.asList(files);
    }

    public String readFile(File f) throws IOException {

        try (BufferedReader br =
                     new BufferedReader(
                             new InputStreamReader(
                                     new FileInputStream(f),
                                     StandardCharsets.UTF_8))) {

            StringBuilder sb = new StringBuilder();
            String line;

            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }

            String contenido = sb.toString();

            // =====================================================
            // TODO 2: DESCIFRAR MENSAJE
            //
            // Cuando los mensajes estén cifrados con AES,
            // el contenido del archivo será ilegible.
            //
            // Aquí habrá que:
            //
            // 1) Leer el texto cifrado.
            // 2) Descifrarlo con la misma clave AES.
            // 3) Devolver el mensaje ya descifrado.
            //
            // =====================================================

            return contenido;
        }
    }
}
