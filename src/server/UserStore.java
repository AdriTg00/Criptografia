package server;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.*;

/*
=========================================================
USERSTORE
=========================================================

Esta clase:
- Carga los usuarios desde users.txt
- Comprueba usuario y contraseña

Ahora mismo es INSEGURA porque:
- Guarda la contraseña real en texto normal.

En la versión segura hay que:
- Guardar HASH + SALT.
- No guardar nunca la contraseña real.
*/

public class UserStore {

    public static class User {
        public final String username;
        public final String passwordPlain; // INSEGURO (v1)
        public final Role role;

        public User(String username, String passwordPlain, Role role) {
            this.username = username;
            this.passwordPlain = passwordPlain;
            this.role = role;
        }
    }

    public enum Role {
        USER, ADMIN, AUDITOR
    }

    private final Map<String, User> users = new HashMap<>();

    public UserStore(String path) {
        load(path);
    }

    private void load(String path) {
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {

            String line;

            while ((line = br.readLine()) != null) {

                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                String[] parts = line.split(":");
                if (parts.length != 3) continue;

                String username = parts[0].trim();
                String password = parts[1].trim();
                Role role = Role.valueOf(parts[2].trim().toUpperCase());

                users.put(username, new User(username, password, role));
            }

        } catch (IOException e) {
            System.err.println("Error leyendo users.txt: " + e);
        }
    }

    public Optional<User> authenticate(String username, String password) {

        User u = users.get(username);
        if (u == null) return Optional.empty();

        // =====================================================
        // TODO 1: AUTENTICACIÓN SEGURA
        //
        // Ahora mismo se compara así:
        //     contraseñaReal.equals(contraseñaEscrita)
        //
        // En la versión segura hay que:
        //
        // 1) Guardar HASH + SALT en vez de contraseña real.
        // 2) Cuando el usuario escriba su contraseña:
        //    - Calcular su HASH.
        //    - Comparar HASH con HASH.
        //
        // Ejemplo:
        //     hash(password + salt) == hashGuardado
        //
        // =====================================================

        if (u.passwordPlain.equals(password)) {
            return Optional.of(u);
        }

        return Optional.empty();
    }

}

