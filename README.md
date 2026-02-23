# cpp-s3-uploader-libcurl-openssl

A minimal C++ implementation of an S3-compatible file uploader using:

- **libcurl** for HTTP communication  
- **OpenSSL** for cryptographic signing  
- **AWS Signature Version 4 (SigV4)** authentication  

Designed for embedded, edge, and backend systems that need direct object storage integration without heavy SDK dependencies.

---

## Why this exists

In many production environments — especially embedded systems, edge AI devices, or lightweight services — using the full AWS SDK is not practical due to:

- Large dependency trees  
- Increased binary size  
- Complex build systems  
- Unnecessary features  

This project demonstrates how to:

- Generate AWS Signature v4 requests manually  
- Upload files to S3-compatible object storage  
- Use libcurl + OpenSSL directly  
- Keep the implementation small and auditable  

It is compatible with:

- AWS S3  
- DigitalOcean Spaces  
- MinIO  
- Any S3-compatible endpoint  

---

## Features

- Minimal AWS SigV4 implementation  
- PUT object upload  
- Canonical request generation  
- HMAC-SHA256 signing using OpenSSL  
- Configurable endpoint and region  
- No AWS SDK dependency  
- CMake-based build  

---

## Typical use cases

- Edge devices uploading snapshots  
- PPE detection alerts sending evidence images  
- Embedded Linux systems with constrained resources  
- Lightweight backend services  
- Systems where full AWS SDK is not desirable  

---

## Project structure

```text
cpp-s3-uploader-libcurl-openssl/
├── include/
│   └── s3_uploader.h
├── src/
│   └── s3_uploader.cpp
├── examples/
│   └── upload_example.cpp
├── CMakeLists.txt
└── README.md
```

---

## Design Goals

-Small, understandable implementation
-Explicit SigV4 signing logic
-No hidden magic
-Portable across Linux and Windows
-Suitable for integration into larger C++ systems

This is not a full S3 client — it is a focused uploader component.

---

## Planned API (preview)

```cpp
S3Uploader uploader({
    .access_key = "...",
    .secret_key = "...",
    .region = "us-east-1",
    .endpoint = "https://s3.amazonaws.com"
});

bool success = uploader.upload_file(
    "my-bucket",
    "path/in/bucket/image.jpg",
    "local_image.jpg"
);
```

---

## Build

Requires:

-CMake 3.10+
-libcurl
-OpenSSL

```Bash
mkdir build
cd build
cmake ..
cmake --build .
```

---

## Disclaimer

This implementation is intended for educational and lightweight production use.
It does not implement:

-Multipart uploads
-Retries with backoff
-Full S3 API coverage
-Presigned URLs

Those can be added as extensions.

---
