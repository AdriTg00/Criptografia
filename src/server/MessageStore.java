package server;

import crypto.HybridCrypto;

import javax.crypto.AEADBadTagException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.*;

public class MessageStore {

    private final File baseDir;
    private final SimpleDateFormat fmt =
            new SimpleDateFormat("yyyyMMdd_HHmmss");

    public MessageStore(String dir) {
        this.baseDir = new File(dir);

        if (!baseDir.exists()) baseDir.mkdirs();
    }

    // 🔐 Guardar mensaje cifrado
    public File storeMessage(String username, String message)
            throws Exception {

        String ts = fmt.format(new Date());
        File f = new File(baseDir,
                username + "_" + ts + ".bin");  // extensión binaria

        // Convertir mensaje a bytes
        byte[] data = message.getBytes(StandardCharsets.UTF_8);

        // 🔐 Cifrar usando esquema híbrido
        byte[] encryptedData = HybridCrypto.encrypt(data);

        // Guardar bytes cifrados
        Files.write(f.toPath(), encryptedData);

        return f;
    }

    // 📂 Listar mensajes de un usuario
    public List<File> listMessagesForUser(String username) {

        File[] files = baseDir.listFiles(
                (d, name) ->
                        name.startsWith(username + "_")
                                && name.endsWith(".bin"));

        if (files == null)
            return Collections.emptyList();

        Arrays.sort(files,
                Comparator.comparing(File::getName)
                        .reversed());

        return Arrays.asList(files);
    }

    // 📂 Listar todos los mensajes (ADMIN)
    public List<File> listAllMessages() {

        File[] files = baseDir.listFiles(
                (d, name) -> name.endsWith(".bin"));

        if (files == null)
            return Collections.emptyList();

        Arrays.sort(files,
                Comparator.comparing(File::getName)
                        .reversed());

        return Arrays.asList(files);
    }

    // 🔓 Leer y descifrar mensaje
    public String readFile(File f) {

        try {

            byte[] fileBytes = Files.readAllBytes(f.toPath());

            // 🔓 Descifrar con HybridCrypto
            byte[] decrypted = HybridCrypto.decrypt(fileBytes);

            return new String(decrypted, StandardCharsets.UTF_8);

        } catch (AEADBadTagException e) {

            // Detecta manipulación (integridad rota)
            return "[ERROR: Fichero manipulado o corrupto]";

        } catch (Exception e) {

            return "[ERROR: No se pudo descifrar el fichero]";
        }
    }
}
