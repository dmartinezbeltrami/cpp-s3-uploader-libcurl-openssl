#pragma once

#include <string>
#include <vector>

// Basic configuration for an S3-compatible endpoint.
struct S3Config {
    std::string access_key;   // e.g. "AKIA..."
    std::string secret_key;   // e.g. "wJalrXUtnFEMI..."
    std::string region;       // e.g. "us-east-1"
    std::string endpoint;     // e.g. "https://s3.amazonaws.com" or DO Spaces endpoint
};

// Minimal S3-compatible uploader using libcurl + OpenSSL.
// This is focused on a single operation: PUT object.
class S3Uploader {
public:
    explicit S3Uploader(S3Config config);

    // Uploads a local file to the given bucket + object key.
    // Returns true on success, false on failure.
    //
    // Example:
    //   S3Uploader uploader(cfg);
    //   bool ok = uploader.upload_file("my-bucket", "path/in/bucket/image.jpg", "local.jpg");
    //
    bool upload_file(const std::string& bucket,
                     const std::string& object_key,
                     const std::string& local_path);

private:
    S3Config config_;

    // Helper to build ISO8601 timestamps: "YYYYMMDDTHHMMSSZ" and "YYYYMMDD".
    struct Timestamp {
        std::string amz_datetime; // e.g. "20250220T153045Z"
        std::string date;         // e.g. "20250220"
    };

    static Timestamp make_timestamp();

    // Helper to compute SHA256 hex of a payload.
    static std::string sha256_hex(const std::string& data);

    // Helper to compute HMAC-SHA256 and return raw bytes.
    static std::vector<unsigned char> hmac_sha256(const std::string& key,
                                                  const std::string& message);

    // Helper to compute HMAC-SHA256 and return hex string.
    static std::string hmac_sha256_hex(const std::string& key,
                                       const std::string& message);

    // Builds the canonical request string for SigV4.
    static std::string build_canonical_request(const std::string& http_method,
                                               const std::string& canonical_uri,
                                               const std::string& canonical_query_string,
                                               const std::string& canonical_headers,
                                               const std::string& signed_headers,
                                               const std::string& payload_hash);

    // Builds the string to sign for SigV4.
    static std::string build_string_to_sign(const std::string& amz_datetime,
                                            const std::string& date,
                                            const std::string& region,
                                            const std::string& service,
                                            const std::string& canonical_request_hash);

    // Derives the signing key: HMAC("AWS4" + secret_key, date/region/service/"aws4_request").
    static std::string derive_signing_key(const std::string& secret_key,
                                          const std::string& date,
                                          const std::string& region,
                                          const std::string& service);

    // Formats the Authorization header value.
    static std::string build_authorization_header(const std::string& access_key,
                                                  const std::string& date,
                                                  const std::string& region,
                                                  const std::string& service,
                                                  const std::string& signed_headers,
                                                  const std::string& signature);

    // Internal method to actually perform a PUT upload using libcurl.
    bool perform_put(const std::string& bucket,
                     const std::string& object_key,
                     const std::string& payload,
                     const std::string& payload_hash);
};