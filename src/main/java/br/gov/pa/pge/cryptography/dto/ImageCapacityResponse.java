package br.gov.pa.pge.cryptography.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ImageCapacityResponse {
    private int maxFileSizeBytes;
    private int imageWidth;
    private int imageHeight;
    private int totalPixels;
    private String message;
}

