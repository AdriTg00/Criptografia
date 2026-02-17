package crypto;

import javax.crypto.SecretKey;
import javax.crypto.AEADBadTagException;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;

public class HybridCrypto {

    public static byte[] encrypt(byte[] data) throws Exception {

        // 1️⃣ Generar clave AES
        SecretKey aesKey = AESUtil.generateKey();

        // 2️⃣ Generar IV
        byte[] iv = AESUtil.generateIV();

        // 3️⃣ Cifrar mensaje con AES-GCM
        byte[] cipherText = AESUtil.encrypt(data, aesKey, iv);

        // 4️⃣ Cifrar clave AES con RSA pública
        PublicKey publicKey = RSAUtil.getPublicKey();
        byte[] encryptedKey = RSAUtil.encrypt(aesKey.getEncoded(), publicKey);

        // 5️⃣ Construir formato final:
        // [4 bytes longitud clave]
        // [clave cifrada]
        // [IV]
        // [cipherText]

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        ByteBuffer lenBuffer = ByteBuffer.allocate(4);
        lenBuffer.putInt(encryptedKey.length);

        output.write(lenBuffer.array());
        output.write(encryptedKey);
        output.write(iv);
        output.write(cipherText);

        return output.toByteArray();
    }

    public static byte[] decrypt(byte[] fileData) throws Exception {

        ByteBuffer buffer = ByteBuffer.wrap(fileData);

        // 1️⃣ Leer longitud clave
        int keyLength = buffer.getInt();

        // 2️⃣ Extraer clave cifrada
        byte[] encryptedKey = new byte[keyLength];
        buffer.get(encryptedKey);

        // 3️⃣ Descifrar clave AES con RSA privada
        PrivateKey privateKey = RSAUtil.getPrivateKey();
        byte[] aesKeyBytes = RSAUtil.decrypt(encryptedKey, privateKey);
        SecretKey aesKey = AESUtil.restoreKey(aesKeyBytes);

        // 4️⃣ Extraer IV
        byte[] iv = new byte[12];
        buffer.get(iv);

        // 5️⃣ Extraer ciphertext
        byte[] cipherText = new byte[buffer.remaining()];
        buffer.get(cipherText);

        // 6️⃣ Descifrar (si está manipulado → lanza AEADBadTagException)
        return AESUtil.decrypt(cipherText, aesKey, iv);
    }
}
