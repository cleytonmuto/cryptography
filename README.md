# Cryptography Tools - Spring Boot Web Application

A web-based cryptography application providing OpenSSL-based encryption and decryption services.

## Features

### 🔑 RSA Key Pair Generation
- Generate RSA 2048-bit public/private key pairs
- Export keys in PEM format (standard OpenSSL format)
- Download keys as .pem files
- Supports generating both keys together or individually

### 🔐 RSA File Encryption/Decryption
- Encrypt files using RSA public key encryption
- Decrypt files using RSA private key decryption
- Supports large files with chunk-based encryption

### 🔒 AES File Encryption/Decryption
- Encrypt files using AES-256-GCM with password
- Decrypt files using AES-256-GCM with password
- Secure password-based encryption

### ✍️ Digital Signatures
- Sign files using RSA private key
- Verify file signatures using RSA public key
- SHA-256 with RSA signature algorithm

### 🔢 File Hashing
- Generate MD5 hash of files
- Generate SHA-256 hash of files
- Useful for file integrity verification

## Technology Stack

- **Spring Boot 4.0.0**
- **Java 25**
- **Java Cryptography Architecture (JCA)**
- **RESTful API**
- **Modern Web UI**

## Getting Started

### Prerequisites
- Java 25 or higher
- Maven 3.6+

### Running the Application

1. Build the project:
```bash
mvn clean install
```

2. Run the application:
```bash
mvn spring-boot:run
```

3. Open your browser and navigate to:
```
http://localhost:8080
```

## API Endpoints

### Generate Key Pair
- **POST** `/api/crypto/generate-keypair` - Returns both keys in one PEM file
- **POST** `/api/crypto/generate-keypair/public` - Returns public key only
- **POST** `/api/crypto/generate-keypair/private` - Returns private key only
- Returns: PEM format file download (.pem)

### RSA Encryption
- **POST** `/api/crypto/encrypt/rsa`
- Parameters: `file` (multipart), `publicKey` (string)
- Returns: Encrypted file download

### RSA Decryption
- **POST** `/api/crypto/decrypt/rsa`
- Parameters: `file` (multipart), `privateKey` (string)
- Returns: Decrypted file download

### AES Encryption
- **POST** `/api/crypto/encrypt/aes`
- Parameters: `file` (multipart), `password` (string)
- Returns: Encrypted file download

### AES Decryption
- **POST** `/api/crypto/decrypt/aes`
- Parameters: `file` (multipart), `password` (string)
- Returns: Decrypted file download

### Sign File
- **POST** `/api/crypto/sign/rsa`
- Parameters: `file` (multipart), `privateKey` (string)
- Returns: Signature file download

### Verify Signature
- **POST** `/api/crypto/verify/rsa`
- Parameters: `file` (multipart), `signature` (multipart), `publicKey` (string)
- Returns: Verification result message

### Generate File Hash
- **POST** `/api/crypto/hash`
- Parameters: `file` (multipart)
- Returns: JSON with MD5 and SHA-256 hash values

## Security Features

- **RSA 2048-bit** encryption for asymmetric cryptography
- **AES-256-GCM** for symmetric encryption with authenticated encryption
- **SHA-256 with RSA** for digital signatures
- Secure password-based key derivation using SHA-256
- Chunk-based encryption for large files

## File Upload Limits

- Maximum file size: 100MB
- Maximum request size: 100MB

## Usage Examples

### 1. Generate Key Pair
1. Navigate to "Generate Key Pair" tab
2. Choose one of the options:
   - **Generate Both Keys**: Downloads a single file with both public and private keys
   - **Generate Public Key Only**: Downloads only the public key
   - **Generate Private Key Only**: Downloads only the private key
3. Keys are downloaded in PEM format (.pem files)
4. Save your keys securely - especially the private key!

### 2. Encrypt a File with RSA
1. Go to "RSA Encrypt" tab
2. Select a file to encrypt
3. Paste the recipient's public key
4. Click "Encrypt File"
5. Download the encrypted file (.encrypted)

### 3. Decrypt a File with RSA
1. Go to "RSA Decrypt" tab
2. Select the encrypted file
3. Paste your private key
4. Click "Decrypt File"
5. Download the decrypted file

### 4. Encrypt a File with AES
1. Go to "AES Encrypt" tab
2. Select a file to encrypt
3. Enter a strong password
4. Click "Encrypt File"
5. Download the encrypted file (.aes)

### 5. Decrypt a File with AES
1. Go to "AES Decrypt" tab
2. Select the encrypted file
3. Enter the same password used for encryption
4. Click "Decrypt File"
5. Download the decrypted file

### 6. Sign a File
1. Go to "Sign File" tab
2. Select the file to sign
3. Paste your private key
4. Click "Sign File"
5. Download the signature file (.sig)

### 7. Verify a Signature
1. Go to "Verify Signature" tab
2. Select the original file
3. Select the signature file
4. Paste the signer's public key
5. Click "Verify Signature"
6. View the verification result

### 8. Generate File Hash
1. Go to "File Hash" tab
2. Select a file
3. Click "Generate Hash"
4. View MD5 and SHA-256 hash values
5. Copy hashes to clipboard for verification

## Project Structure

```
src/
├── main/
│   ├── java/
│   │   └── br/gov/pa/pge/cryptography/
│   │       ├── controller/
│   │       │   ├── CryptographyController.java
│   │       │   └── IndexController.java
│   │       ├── dto/
│   │       │   ├── EncryptionRequest.java
│   │       │   └── KeyPairResponse.java
│   │       ├── service/
│   │       │   └── CryptographyService.java
│   │       └── CryptographyApplication.java
│   └── resources/
│       ├── static/
│       │   └── index.html
│       └── application.properties
└── test/
```

## Notes

- **Keep private keys secure**: Never share your private keys
- **PEM format**: Keys are generated in standard PEM format, compatible with OpenSSL and most cryptographic tools
- **Key format**: The application accepts both PEM format (with headers/footers) and raw Base64 keys
- **Strong passwords**: Use strong, unique passwords for AES encryption
- **Key backup**: Always backup your keys in a secure location
- **File compatibility**: Encrypted files are binary and not human-readable

## License

This project is developed for educational and internal use.

