package br.gov.pa.pge.cryptography.controller;

import br.gov.pa.pge.cryptography.dto.ImageCapacityResponse;
import br.gov.pa.pge.cryptography.service.SteganographyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/steganography")
@CrossOrigin(origins = "*")
public class SteganographyController {

    @Autowired
    private SteganographyService steganographyService;

    /**
     * Calculate maximum file size that can be hidden in an image
     */
    @PostMapping(value = "/capacity", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ImageCapacityResponse> calculateCapacity(
            @RequestParam("image") MultipartFile imageFile) {
        try {
            // Validate image format
            String imageFilename = imageFile.getOriginalFilename();
            if (imageFilename == null || (!imageFilename.toLowerCase().endsWith(".jpg") && 
                !imageFilename.toLowerCase().endsWith(".jpeg"))) {
                return ResponseEntity.badRequest()
                    .body(new ImageCapacityResponse(0, 0, 0, 0, "Invalid image format. Only JPG/JPEG images are supported."));
            }

            byte[] imageData = imageFile.getBytes();
            int maxFileSize = steganographyService.calculateMaxFileSize(imageData);
            int[] dimensions = steganographyService.getImageDimensions(imageData);
            
            ImageCapacityResponse response = new ImageCapacityResponse(
                maxFileSize,
                dimensions[0],
                dimensions[1],
                dimensions[0] * dimensions[1],
                "Capacity calculated successfully"
            );
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                .body(new ImageCapacityResponse(0, 0, 0, 0, "Error calculating capacity: " + e.getMessage()));
        }
    }

    /**
     * Hide a file inside a JPG image
     */
    @PostMapping(value = "/hide", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Resource> hideFile(
            @RequestParam("image") MultipartFile imageFile,
            @RequestParam("file") MultipartFile fileToHide,
            @RequestParam("password") String password) {
        try {
            // Validate image format
            String imageFilename = imageFile.getOriginalFilename();
            if (imageFilename == null || !imageFilename.toLowerCase().endsWith(".jpg") && 
                !imageFilename.toLowerCase().endsWith(".jpeg")) {
                return ResponseEntity.badRequest().build();
            }

            byte[] imageData = imageFile.getBytes();
            byte[] fileData = fileToHide.getBytes();
            String filename = fileToHide.getOriginalFilename();
            if (filename == null) {
                filename = "hidden_file";
            }

            byte[] stegoImage = steganographyService.hideFileInImage(imageData, fileData, filename, password);

            ByteArrayResource resource = new ByteArrayResource(stegoImage);
            String outputFilename = imageFilename != null ? 
                imageFilename.replaceFirst("\\.(jpg|jpeg)$", "_stego.jpg") : "stego_image.jpg";

            return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + outputFilename + "\"")
                .contentType(MediaType.IMAGE_JPEG)
                .contentLength(stegoImage.length)
                .body(resource);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Extract a hidden file from a JPG image
     */
    @PostMapping(value = "/extract", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Resource> extractFile(
            @RequestParam("image") MultipartFile imageFile,
            @RequestParam("password") String password) {
        try {
            byte[] imageData = imageFile.getBytes();
            SteganographyService.HiddenFileData hiddenFile = steganographyService.extractFileFromImage(imageData, password);

            ByteArrayResource resource = new ByteArrayResource(hiddenFile.getData());
            String filename = hiddenFile.getFilename();

            return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(hiddenFile.getData().length)
                .body(resource);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }
}

