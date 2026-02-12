package util;

import protocol.Protocol;

import java.io.BufferedReader;
import java.io.IOException;

/** Utilidades para leer respuestas multilinea hasta END. */
public class IOUtil {

    public static void readMultilineUntilEnd(BufferedReader in) throws IOException {
        while (true) {
            String line = in.readLine();
            if (line == null) return;
            if (line.equals(Protocol.END)) return;
            System.out.println("SERVER> " + line);
        }
    }
}
