package br.gov.pa.pge.cryptography.dto;

import lombok.Data;

@Data
public class EncryptionRequest {
    private String publicKey; // For RSA encryption
    private String password; // For AES encryption
    private String encryptionType; // "RSA" or "AES"
}

