package br.gov.pa.pge.cryptography.controller;

import br.gov.pa.pge.cryptography.dto.HashResponse;
import br.gov.pa.pge.cryptography.dto.KeyPairResponse;
import br.gov.pa.pge.cryptography.service.CryptographyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.security.KeyPair;

@RestController
@RequestMapping("/api/crypto")
@CrossOrigin(origins = "*")
public class CryptographyController {

    @Autowired
    private CryptographyService cryptographyService;

    /**
     * Generate RSA key pair
     */
    @PostMapping("/generate-keypair")
    public ResponseEntity<KeyPairResponse> generateKeyPair() {
        try {
            KeyPair keyPair = cryptographyService.generateRSAKeyPair();
            String publicKey = cryptographyService.publicKeyToString(keyPair.getPublic());
            String privateKey = cryptographyService.privateKeyToString(keyPair.getPrivate());
            
            KeyPairResponse response = new KeyPairResponse(
                publicKey,
                privateKey,
                "Key pair generated successfully"
            );
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                .body(new KeyPairResponse(null, null, "Error generating key pair: " + e.getMessage()));
        }
    }

    /**
     * Encrypt file using RSA
     */
    @PostMapping(value = "/encrypt/rsa", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Resource> encryptRSA(
            @RequestParam("file") MultipartFile file,
            @RequestParam("publicKey") String publicKey) {
        try {
            byte[] fileContent = file.getBytes();
            byte[] encryptedData = cryptographyService.encryptRSA(fileContent, publicKey);
            
            ByteArrayResource resource = new ByteArrayResource(encryptedData);
            String filename = file.getOriginalFilename();
            String encryptedFilename = (filename != null ? filename : "file") + ".encrypted";
            
            return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + encryptedFilename + "\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(encryptedData.length)
                .body(resource);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Decrypt file using RSA
     */
    @PostMapping(value = "/decrypt/rsa", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Resource> decryptRSA(
            @RequestParam("file") MultipartFile file,
            @RequestParam("privateKey") String privateKey) {
        try {
            byte[] encryptedData = file.getBytes();
            byte[] decryptedData = cryptographyService.decryptRSA(encryptedData, privateKey);
            
            ByteArrayResource resource = new ByteArrayResource(decryptedData);
            String filename = file.getOriginalFilename();
            String decryptedFilename = filename != null && filename.endsWith(".encrypted") 
                ? filename.substring(0, filename.length() - ".encrypted".length())
                : (filename != null ? filename : "file") + ".decrypted";
            
            return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + decryptedFilename + "\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(decryptedData.length)
                .body(resource);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Encrypt file using AES
     */
    @PostMapping(value = "/encrypt/aes", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Resource> encryptAES(
            @RequestParam("file") MultipartFile file,
            @RequestParam("password") String password) {
        try {
            byte[] fileContent = file.getBytes();
            byte[] encryptedData = cryptographyService.encryptAES(fileContent, password);
            
            ByteArrayResource resource = new ByteArrayResource(encryptedData);
            String filename = file.getOriginalFilename();
            String encryptedFilename = (filename != null ? filename : "file") + ".aes";
            
            return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + encryptedFilename + "\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(encryptedData.length)
                .body(resource);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Decrypt file using AES
     */
    @PostMapping(value = "/decrypt/aes", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Resource> decryptAES(
            @RequestParam("file") MultipartFile file,
            @RequestParam("password") String password) {
        try {
            byte[] encryptedData = file.getBytes();
            byte[] decryptedData = cryptographyService.decryptAES(encryptedData, password);
            
            ByteArrayResource resource = new ByteArrayResource(decryptedData);
            String filename = file.getOriginalFilename();
            String decryptedFilename = filename != null && filename.endsWith(".aes") 
                ? filename.substring(0, filename.length() - ".aes".length())
                : (filename != null ? filename : "file") + ".decrypted";
            
            return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + decryptedFilename + "\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(decryptedData.length)
                .body(resource);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Sign file using RSA private key
     */
    @PostMapping(value = "/sign/rsa", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Resource> signRSA(
            @RequestParam("file") MultipartFile file,
            @RequestParam("privateKey") String privateKey) {
        try {
            byte[] fileContent = file.getBytes();
            byte[] signature = cryptographyService.signRSA(fileContent, privateKey);
            
            ByteArrayResource resource = new ByteArrayResource(signature);
            String filename = file.getOriginalFilename();
            String signatureFilename = (filename != null ? filename : "file") + ".sig";
            
            return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + signatureFilename + "\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(signature.length)
                .body(resource);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Verify RSA signature
     */
    @PostMapping(value = "/verify/rsa", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> verifyRSA(
            @RequestParam("file") MultipartFile file,
            @RequestParam("signature") MultipartFile signatureFile,
            @RequestParam("publicKey") String publicKey) {
        try {
            byte[] fileContent = file.getBytes();
            byte[] signature = signatureFile.getBytes();
            boolean isValid = cryptographyService.verifyRSASignature(fileContent, signature, publicKey);
            
            String message = isValid 
                ? "Signature is valid" 
                : "Signature is invalid";
            return ResponseEntity.ok(message);
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                .body("Error verifying signature: " + e.getMessage());
        }
    }

    /**
     * Generate MD5 and SHA-256 hashes of a file
     */
    @PostMapping(value = "/hash", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<HashResponse> generateHash(
            @RequestParam("file") MultipartFile file) {
        try {
            byte[] fileContent = file.getBytes();
            String md5Hash = cryptographyService.generateMD5Hash(fileContent);
            String sha256Hash = cryptographyService.generateSHA256Hash(fileContent);
            
            HashResponse response = new HashResponse(
                md5Hash,
                sha256Hash,
                "Hash generated successfully"
            );
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                .body(new HashResponse(null, null, "Error generating hash: " + e.getMessage()));
        }
    }
}

