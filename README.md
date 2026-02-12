# SecureDrop v1 (INSEGURA) — Proyecto de Securización (Java + Sockets)

---

## ¿Qué es esta aplicación?

SecureDrop v1 es una aplicación **cliente-servidor por consola** desarrollada en Java utilizando **sockets TCP**.

El sistema permite:

- Iniciar sesión (login)
- Enviar mensajes al servidor
- Listar mis propios mensajes
- (Admin) Listar todos los mensajes almacenados en el servidor

Actualmente la aplicación es **funcional pero insegura a propósito**.  
El objetivo del proyecto es convertirla en una versión segura (SecureDrop v2).

---

## ¿Cómo funciona exactamente?

### 1️ El servidor

Cuando se ejecuta `ServerMain`:

- Abre el puerto 15000
- Carga los usuarios desde `users.txt`
- Espera conexiones entrantes de clientes
- Guarda los mensajes en la carpeta `data/`

No utiliza cifrado ni TLS en esta versión.

---

### 2️ El cliente

Cuando se ejecuta `ClientMain`:

- Se conecta al servidor mediante `Socket`
- Solicita usuario y contraseña
- Envía el comando:

```
LOGIN usuario contraseña
```

Si las credenciales son correctas, el servidor responde:

```
OK Autenticado como usuario (ROL)
```

---

## Menú del cliente

Una vez autenticado, el usuario puede:

### 1) Enviar mensaje

- El cliente envía el mensaje al servidor con el comando:

```
SEND Hola este es mi mensaje
```

- El servidor lo guarda como archivo en la carpeta `data/`.
- El contenido se almacena en texto plano (INSEGURO).

Ejemplo de archivo guardado:

```
juan_20260211_1530.txt
```

Contenido:

```
From: juan
Date: 11/02/2026
Message:
Hola este es mi mensaje
```

---

### 2) Listar mis mensajes

- El servidor busca los archivos que comienzan por el nombre del usuario.
- Devuelve el contenido completo al cliente.
- El usuario ve todos sus mensajes almacenados.

---

### 3) (Admin) Listar TODOS los mensajes

Si el usuario tiene rol ADMIN:

- El servidor recorre toda la carpeta `data/`.
- Devuelve todos los mensajes de todos los usuarios.
- Simula un administrador con acceso global.

---

## ¿Qué problemas tiene esta versión? 

- ❌ Contraseñas almacenadas en texto plano (`users.txt`)
- ❌ Comunicación sin cifrado (Socket normal)
- ❌ Mensajes almacenados visibles en disco
- ❌ Sin política de intentos fallidos
- ❌ Sin bloqueo de cuentas
- ❌ Sin logs de seguridad
- ❌ Manejo inseguro de errores (stacktrace visible)
- ❌ Sin validación de tamaño o entrada

---

## ¿Cuál es vuestro objetivo?

Transformar SecureDrop v1 en SecureDrop v2 implementando:

- TLS en las comunicaciones
- Hash + salt para contraseñas
- Cifrado AES para datos almacenados
- RSA para intercambio seguro de claves
- Control de acceso por roles robusto
- Política de seguridad
- Logs de auditoría
- Buenas prácticas de programación segura

---



## Credenciales de prueba (en `users.txt`)
- admin / admin123  (ADMIN)
- juan / 1234       (USER)
- maria / abcd      (USER)
- auditor / audit   (AUDITOR)

---

## Estructura del proyecto
- `src/`
  - `ServerMain.java` → arranca el servidor
  - `ClientMain.java` → arranca el cliente
  - `protocol/Protocol.java` → constantes del protocolo
  - `server/ClientHandler.java` → atiende a cada cliente
  - `server/UserStore.java` → usuarios (lee `users.txt`)
  - `server/MessageStore.java` → guarda/lista mensajes en `data/`
  - `server/SecurityPolicy.java` → (básico) política (intentos/lock) **TODO**
  - `util/IOUtil.java` → utilidades de IO
- `users.txt` → usuarios (INSEGURO: contraseñas visbles)
- `data/` → donde el servidor guarda mensajes (INSEGURO: Se guardan en texto legible, sin ningún tipo de cifrado).En cuanto ejecutéis ServerMain se generará sola.
- `ssl/` → Carpeta reservada para los archivos de seguridad en v2 (keystore, truststore y certificados para TLS). En esta versión puede no aparecer porque aún no contiene archivos.


---

## Antes de empezar el proyecto

Antes de modificar el código, debes comprobar que la aplicación funciona correctamente.

---


## 1.Ejecutar el servidor

Debe aparecer:

=== SecureDrop Server v1 (INSEGURA) ===
Puerto: 15000

El servidor queda esperando conexiones.

---

## 2.Ejecutar el cliente

Aparecerá:

Servidor (host) [localhost]:

Si el servidor está en el mismo ordenador:

- Pulsar Enter
- En `Puerto [15000]:` pulsar Enter

---

## 3.Iniciar sesión

Usar una de estas cuentas:

admin / admin123  
juan / 1234  
maria / abcd  
auditor / audit  

Si todo funciona correctamente aparecerá:

SERVER> OK Autenticado como ...

---

## 4.Probar funcionalidades

- Opción 1 → Enviar mensaje
- Opción 2 → Listar mis mensajes
- Opción 3 → (Solo ADMIN) listar todos los mensajes

---

## 5.Comprobar almacenamiento

Ir a la carpeta del proyecto y abrir:

data/

Debe haberse creado un archivo con el mensaje en texto plano.

---


## Próximo paso

Buscar en el código los comentarios marcados como:

```java
// TODO(v2): ...
```

Esos indican exactamente qué debéis implementar en la versión segura.

---
