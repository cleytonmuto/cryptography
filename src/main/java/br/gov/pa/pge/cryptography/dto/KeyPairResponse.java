package br.gov.pa.pge.cryptography.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class KeyPairResponse {
    private String publicKey;
    private String privateKey;
    private String message;
}

