package br.gov.pa.pge.cryptography.service;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

@Service
public class SteganographyService {

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;

    /**
     * Calculate maximum file size that can be hidden in an image
     * Returns maximum file size in bytes (before encryption overhead)
     */
    public int calculateMaxFileSize(byte[] imageData) throws IOException {
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(imageData));
        if (image == null) {
            throw new IOException("Invalid image format");
        }

        int totalPixels = image.getWidth() * image.getHeight();
        // Each pixel can store 3 bits (one per RGB channel)
        // Total capacity in bytes = (totalPixels * 3) / 8
        int totalCapacityBytes = (totalPixels * 3) / 8;
        
        // Overhead: 4 bytes (filename length) + max filename (assume 255 bytes) + 4 bytes (file size) + 28 bytes (IV + GCM tag)
        int overhead = 4 + 255 + 4 + 28; // 291 bytes overhead
        
        // Maximum file size = total capacity - overhead
        int maxFileSize = totalCapacityBytes - overhead;
        
        // Ensure non-negative
        return Math.max(0, maxFileSize);
    }

    /**
     * Get image dimensions
     */
    public int[] getImageDimensions(byte[] imageData) throws IOException {
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(imageData));
        if (image == null) {
            throw new IOException("Invalid image format");
        }
        return new int[]{image.getWidth(), image.getHeight()};
    }

    /**
     * Hide a file inside a JPG image using LSB steganography
     * Format: [filename_length:4 bytes][filename:variable][file_size:4 bytes][encrypted_file_data:variable]
     */
    public byte[] hideFileInImage(byte[] imageData, byte[] fileData, String filename, String password) throws Exception {
        // Read the image
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(imageData));
        if (image == null) {
            throw new IOException("Invalid image format");
        }

        // Encrypt the file data
        byte[] encryptedData = encryptFile(fileData, password);

        // Prepare metadata: filename length (4 bytes) + filename + file size (4 bytes) + encrypted data
        byte[] filenameBytes = filename.getBytes(StandardCharsets.UTF_8);
        int filenameLength = filenameBytes.length;
        int fileSize = encryptedData.length;

        // Calculate total data size
        int totalDataSize = 4 + filenameLength + 4 + fileSize;
        
        // Calculate required pixels (each pixel can store 3 bits in RGB, but we'll use 1 bit per channel for safety)
        int requiredPixels = (totalDataSize * 8) / 3;
        int totalPixels = image.getWidth() * image.getHeight();
        
        if (requiredPixels > totalPixels) {
            throw new IOException("Image is too small to hide the file. Required: " + requiredPixels + " pixels, Available: " + totalPixels);
        }

        // Create metadata buffer
        ByteBuffer metadataBuffer = ByteBuffer.allocate(4 + filenameLength + 4);
        metadataBuffer.putInt(filenameLength);
        metadataBuffer.put(filenameBytes);
        metadataBuffer.putInt(fileSize);
        byte[] metadata = metadataBuffer.array();

        // Combine metadata and encrypted data
        ByteBuffer dataBuffer = ByteBuffer.allocate(totalDataSize);
        dataBuffer.put(metadata);
        dataBuffer.put(encryptedData);
        byte[] allData = dataBuffer.array();

        // Hide data in image using LSB
        int dataIndex = 0;
        int bitIndex = 0;
        int currentByte = dataIndex < allData.length ? allData[dataIndex] & 0xFF : 0;

        for (int y = 0; y < image.getHeight() && dataIndex < allData.length; y++) {
            for (int x = 0; x < image.getWidth() && dataIndex < allData.length; x++) {
                int rgb = image.getRGB(x, y);
                
                // Extract RGB components
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;

                // Hide 3 bits (one in each color channel)
                if (dataIndex < allData.length) {
                    // Red channel
                    r = (r & 0xFE) | ((currentByte >> (7 - bitIndex)) & 1);
                    bitIndex++;
                    if (bitIndex >= 8) {
                        bitIndex = 0;
                        dataIndex++;
                        if (dataIndex < allData.length) {
                            currentByte = allData[dataIndex] & 0xFF;
                        }
                    }

                    // Green channel
                    if (dataIndex < allData.length) {
                        g = (g & 0xFE) | ((currentByte >> (7 - bitIndex)) & 1);
                        bitIndex++;
                        if (bitIndex >= 8) {
                            bitIndex = 0;
                            dataIndex++;
                            if (dataIndex < allData.length) {
                                currentByte = allData[dataIndex] & 0xFF;
                            }
                        }
                    }

                    // Blue channel
                    if (dataIndex < allData.length) {
                        b = (b & 0xFE) | ((currentByte >> (7 - bitIndex)) & 1);
                        bitIndex++;
                        if (bitIndex >= 8) {
                            bitIndex = 0;
                            dataIndex++;
                            if (dataIndex < allData.length) {
                                currentByte = allData[dataIndex] & 0xFF;
                            }
                        }
                    }
                }

                // Set new RGB value
                int newRgb = (rgb & 0xFF000000) | (r << 16) | (g << 8) | b;
                image.setRGB(x, y, newRgb);
            }
        }

        // Convert image back to byte array
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "jpg", baos);
        return baos.toByteArray();
    }

    /**
     * Extract a hidden file from a JPG image
     */
    public HiddenFileData extractFileFromImage(byte[] imageData, String password) throws Exception {
        // Read the image
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(imageData));
        if (image == null) {
            throw new IOException("Invalid image format");
        }

        // Extract metadata first (filename length + filename + file size = at least 8 bytes)
        byte[] metadataBytes = new byte[8]; // Minimum: 4 bytes filename length + 4 bytes file size
        int bitIndex = 0;
        int byteIndex = 0;
        int currentByte = 0;

        // Extract first 8 bytes to get filename length and file size
        for (int y = 0; y < image.getHeight() && byteIndex < 8; y++) {
            for (int x = 0; x < image.getWidth() && byteIndex < 8; x++) {
                int rgb = image.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;

                // Extract from RGB channels
                for (int channel = 0; channel < 3 && byteIndex < 8; channel++) {
                    int bit = 0;
                    if (channel == 0) bit = r & 1;
                    else if (channel == 1) bit = g & 1;
                    else bit = b & 1;

                    currentByte = (currentByte << 1) | bit;
                    bitIndex++;

                    if (bitIndex >= 8) {
                        metadataBytes[byteIndex] = (byte) currentByte;
                        byteIndex++;
                        bitIndex = 0;
                        currentByte = 0;
                    }
                }
            }
        }

        // Parse metadata
        ByteBuffer metadataBuffer = ByteBuffer.wrap(metadataBytes);
        int filenameLength = metadataBuffer.getInt();
        int fileSize = metadataBuffer.getInt();

        if (filenameLength < 0 || filenameLength > 1024 || fileSize < 0 || fileSize > 10 * 1024 * 1024) {
            throw new IOException("Invalid metadata. File may not be hidden in this image.");
        }

        // Extract filename
        byte[] filenameBytes = new byte[filenameLength];
        int totalBytesToExtract = filenameLength + fileSize;
        byte[] allData = new byte[totalBytesToExtract];

        // Continue extraction from where we left off
        bitIndex = 0;
        byteIndex = 0;
        currentByte = 0;
        int pixelIndex = 0;
        int startPixel = (8 * 8) / 3; // We already extracted 8 bytes

        for (int y = 0; y < image.getHeight() && byteIndex < totalBytesToExtract; y++) {
            for (int x = 0; x < image.getWidth() && byteIndex < totalBytesToExtract; x++) {
                if (pixelIndex < startPixel) {
                    pixelIndex++;
                    continue;
                }

                int rgb = image.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;

                // Extract from RGB channels
                for (int channel = 0; channel < 3 && byteIndex < totalBytesToExtract; channel++) {
                    int bit = 0;
                    if (channel == 0) bit = r & 1;
                    else if (channel == 1) bit = g & 1;
                    else bit = b & 1;

                    currentByte = (currentByte << 1) | bit;
                    bitIndex++;

                    if (bitIndex >= 8) {
                        allData[byteIndex] = (byte) currentByte;
                        byteIndex++;
                        bitIndex = 0;
                        currentByte = 0;
                    }
                }
                pixelIndex++;
            }
        }

        // Separate filename and encrypted data
        System.arraycopy(allData, 0, filenameBytes, 0, filenameLength);
        String filename = new String(filenameBytes, StandardCharsets.UTF_8);

        byte[] encryptedData = new byte[fileSize];
        System.arraycopy(allData, filenameLength, encryptedData, 0, fileSize);

        // Decrypt the file data
        byte[] decryptedData = decryptFile(encryptedData, password);

        return new HiddenFileData(filename, decryptedData);
    }

    /**
     * Encrypt file data using AES-GCM
     */
    private byte[] encryptFile(byte[] data, String password) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[GCM_IV_LENGTH];
        random.nextBytes(iv);

        SecretKey secretKey = deriveKey(password);

        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] cipherText = cipher.doFinal(data);

        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        return byteBuffer.array();
    }

    /**
     * Decrypt file data using AES-GCM
     */
    private byte[] decryptFile(byte[] encryptedData, String password) throws Exception {
        ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);
        byte[] iv = new byte[GCM_IV_LENGTH];
        byteBuffer.get(iv);
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);

        SecretKey secretKey = deriveKey(password);

        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        return cipher.doFinal(cipherText);
    }

    /**
     * Derive AES key from password
     */
    private SecretKey deriveKey(String password) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = digest.digest(password.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(keyBytes, AES_ALGORITHM);
    }

    /**
     * Data class for hidden file information
     */
    public static class HiddenFileData {
        private final String filename;
        private final byte[] data;

        public HiddenFileData(String filename, byte[] data) {
            this.filename = filename;
            this.data = data;
        }

        public String getFilename() {
            return filename;
        }

        public byte[] getData() {
            return data;
        }
    }
}

