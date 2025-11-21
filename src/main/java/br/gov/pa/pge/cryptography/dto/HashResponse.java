package br.gov.pa.pge.cryptography.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class HashResponse {
    private String md5Hash;
    private String sha256Hash;
    private String message;
}

