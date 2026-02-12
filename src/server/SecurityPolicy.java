package server;

import java.util.HashMap;
import java.util.Map;

/*
=========================================================
SECURITY POLICY
=========================================================

Esta clase controla reglas básicas de seguridad.

En la versión segura debe:

1) Contar intentos fallidos de login.
2) Bloquear usuario tras X intentos.
3) Desbloquearlo después de un tiempo.
*/

public class SecurityPolicy {

    // Número máximo de intentos permitidos
    private static final int MAX_INTENTOS = 3;

    // Tiempo de bloqueo en milisegundos (ej: 2 minutos)
    private static final long TIEMPO_BLOQUEO = 2 * 60 * 1000;

    // Guarda número de intentos fallidos
    private final Map<String, Integer> failedAttempts = new HashMap<>();

    // Guarda cuándo se bloqueó el usuario
    private final Map<String, Long> blockedUntil = new HashMap<>();


    // =====================================================
    // TODO 1:
    // Llamar a este método cuando falle el login.
    // Debe:
    // - Aumentar contador.
    // - Si supera MAX_INTENTOS → bloquear usuario.
    // =====================================================
    public void registerFailure(String username) {

        int attempts = failedAttempts.getOrDefault(username, 0) + 1;
        failedAttempts.put(username, attempts);

        if (attempts >= MAX_INTENTOS) {
            blockedUntil.put(username, System.currentTimeMillis() + TIEMPO_BLOQUEO);
        }
    }


    // =====================================================
    // TODO 2:
    // Llamar a este método cuando el login sea correcto.
    // Debe:
    // - Resetear intentos fallidos.
    // - Quitar bloqueo.
    // =====================================================
    public void registerSuccess(String username) {

        failedAttempts.remove(username);
        blockedUntil.remove(username);
    }


    // =====================================================
    // TODO 3:
    // Antes de permitir login, comprobar si el usuario está bloqueado.
    //
    // Si el tiempo de bloqueo ya pasó, desbloquear automáticamente.
    // =====================================================
    public boolean isBlocked(String username) {

        if (!blockedUntil.containsKey(username)) {
            return false;
        }

        long tiempoFin = blockedUntil.get(username);

        if (System.currentTimeMillis() > tiempoFin) {
            blockedUntil.remove(username);
            failedAttempts.remove(username);
            return false;
        }

        return true;
    }
}
