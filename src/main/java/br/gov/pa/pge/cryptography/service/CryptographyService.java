package br.gov.pa.pge.cryptography.service;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class CryptographyService {

    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_ALGORITHM = "AES";
    private static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";
    private static final int RSA_KEY_SIZE = 2048;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;

    /**
     * Generate RSA key pair (public and private keys)
     */
    public KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyPairGenerator.initialize(RSA_KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Convert PublicKey to PEM format string
     */
    public String publicKeyToPEM(PublicKey publicKey) {
        String base64Key = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        return formatPEM(base64Key, "PUBLIC KEY");
    }

    /**
     * Convert PrivateKey to PEM format string
     */
    public String privateKeyToPEM(PrivateKey privateKey) {
        String base64Key = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        return formatPEM(base64Key, "PRIVATE KEY");
    }

    /**
     * Format Base64 key as PEM with headers and line breaks
     */
    private String formatPEM(String base64Key, String keyType) {
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN ").append(keyType).append("-----\n");
        
        // Add line breaks every 64 characters
        for (int i = 0; i < base64Key.length(); i += 64) {
            int end = Math.min(i + 64, base64Key.length());
            pem.append(base64Key.substring(i, end));
            if (end < base64Key.length()) {
                pem.append("\n");
            }
        }
        
        pem.append("\n-----END ").append(keyType).append("-----\n");
        return pem.toString();
    }

    /**
     * Convert PEM or Base64 string to PublicKey
     */
    public PublicKey stringToPublicKey(String publicKeyStr) throws Exception {
        // Remove PEM headers/footers and whitespace if present
        String cleanedKey = cleanPEMKey(publicKeyStr, "PUBLIC KEY");
        byte[] keyBytes = Base64.getDecoder().decode(cleanedKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return keyFactory.generatePublic(spec);
    }

    /**
     * Convert PEM or Base64 string to PrivateKey
     */
    public PrivateKey stringToPrivateKey(String privateKeyStr) throws Exception {
        // Remove PEM headers/footers and whitespace if present
        String cleanedKey = cleanPEMKey(privateKeyStr, "PRIVATE KEY");
        byte[] keyBytes = Base64.getDecoder().decode(cleanedKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return keyFactory.generatePrivate(spec);
    }

    /**
     * Clean PEM key string by removing headers, footers, and whitespace
     */
    private String cleanPEMKey(String keyStr, String keyType) {
        if (keyStr == null) {
            return "";
        }
        
        // Remove PEM headers and footers
        String cleaned = keyStr
            .replace("-----BEGIN " + keyType + "-----", "")
            .replace("-----END " + keyType + "-----", "")
            .replaceAll("\\s", ""); // Remove all whitespace
        
        return cleaned;
    }

    /**
     * Encrypt file content using RSA with public key
     */
    public byte[] encryptRSA(byte[] data, String publicKeyStr) throws Exception {
        PublicKey publicKey = stringToPublicKey(publicKeyStr);
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        
        // RSA can only encrypt data up to key size - 11 bytes (for PKCS1 padding)
        // For larger files, we need to split into chunks
        int maxChunkSize = RSA_KEY_SIZE / 8 - 11;
        ByteBuffer buffer = ByteBuffer.allocate((data.length / maxChunkSize + 1) * (RSA_KEY_SIZE / 8));
        
        int offset = 0;
        while (offset < data.length) {
            int chunkSize = Math.min(maxChunkSize, data.length - offset);
            byte[] chunk = new byte[chunkSize];
            System.arraycopy(data, offset, chunk, 0, chunkSize);
            
            byte[] encryptedChunk = cipher.doFinal(chunk);
            buffer.put(encryptedChunk);
            
            offset += chunkSize;
        }
        
        buffer.flip();
        byte[] result = new byte[buffer.remaining()];
        buffer.get(result);
        return result;
    }

    /**
     * Decrypt file content using RSA with private key
     */
    public byte[] decryptRSA(byte[] encryptedData, String privateKeyStr) throws Exception {
        PrivateKey privateKey = stringToPrivateKey(privateKeyStr);
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        
        int chunkSize = RSA_KEY_SIZE / 8;
        ByteBuffer buffer = ByteBuffer.allocate(encryptedData.length);
        
        int offset = 0;
        while (offset < encryptedData.length) {
            int currentChunkSize = Math.min(chunkSize, encryptedData.length - offset);
            byte[] chunk = new byte[currentChunkSize];
            System.arraycopy(encryptedData, offset, chunk, 0, currentChunkSize);
            
            byte[] decryptedChunk = cipher.doFinal(chunk);
            buffer.put(decryptedChunk);
            
            offset += currentChunkSize;
        }
        
        buffer.flip();
        byte[] result = new byte[buffer.remaining()];
        buffer.get(result);
        return result;
    }

    /**
     * Encrypt file content using AES with password
     */
    public byte[] encryptAES(byte[] data, String password) throws Exception {
        // Generate IV
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[GCM_IV_LENGTH];
        random.nextBytes(iv);

        // Derive key from password
        SecretKey secretKey = deriveAESKey(password);

        // Encrypt
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] cipherText = cipher.doFinal(data);

        // Combine IV and ciphertext
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        return byteBuffer.array();
    }

    /**
     * Decrypt file content using AES with password
     */
    public byte[] decryptAES(byte[] encryptedData, String password) throws Exception {
        // Extract IV
        ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);
        byte[] iv = new byte[GCM_IV_LENGTH];
        byteBuffer.get(iv);
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);

        // Derive key from password
        SecretKey secretKey = deriveAESKey(password);

        // Decrypt
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        return cipher.doFinal(cipherText);
    }

    /**
     * Derive AES key from password using SHA-256
     */
    private SecretKey deriveAESKey(String password) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = digest.digest(password.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(keyBytes, AES_ALGORITHM);
    }

    /**
     * Sign data using RSA private key
     */
    public byte[] signRSA(byte[] data, String privateKeyStr) throws Exception {
        PrivateKey privateKey = stringToPrivateKey(privateKeyStr);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * Verify signature using RSA public key
     */
    public boolean verifyRSASignature(byte[] data, byte[] signature, String publicKeyStr) throws Exception {
        PublicKey publicKey = stringToPublicKey(publicKeyStr);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    /**
     * Generate MD5 hash of file content
     */
    public String generateMD5Hash(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hashBytes = md.digest(data);
        return bytesToHex(hashBytes);
    }

    /**
     * Generate SHA-256 hash of file content
     */
    public String generateSHA256Hash(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(data);
        return bytesToHex(hashBytes);
    }

    /**
     * Convert byte array to hexadecimal string
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}

