#include "s3_uploader.h"

S3Uploader::S3Uploader(S3Config config)
    : config_(std::move(config)) {}

bool S3Uploader::upload_file(const std::string& bucket,
                             const std::string& object_key,
                             const std::string& local_path) {
    // TODO: read file from disk, compute payload hash, sign request, and upload via libcurl.
    // For now, return false to indicate "not implemented".
    (void)bucket;
    (void)object_key;
    (void)local_path;
    return false;
}

// --- Static helper stubs --- //

S3Uploader::Timestamp S3Uploader::make_timestamp() {
    // TODO: implement real timestamp generation (UTC, ISO8601).
    return {"19700101T000000Z", "19700101"};
}

std::string S3Uploader::sha256_hex(const std::string& data) {
    // TODO: implement SHA256 using OpenSSL.
    (void)data;
    return "";
}

std::vector<unsigned char> S3Uploader::hmac_sha256(const std::string& key,
                                                   const std::string& message) {
    // TODO: implement HMAC-SHA256 using OpenSSL.
    (void)key;
    (void)message;
    return {};
}

std::string S3Uploader::hmac_sha256_hex(const std::string& key,
                                        const std::string& message) {
    // TODO: implement using hmac_sha256(...)
    (void)key;
    (void)message;
    return "";
}

std::string S3Uploader::build_canonical_request(const std::string& http_method,
                                                const std::string& canonical_uri,
                                                const std::string& canonical_query_string,
                                                const std::string& canonical_headers,
                                                const std::string& signed_headers,
                                                const std::string& payload_hash) {
    // TODO: implement SigV4 canonical request format.
    (void)http_method;
    (void)canonical_uri;
    (void)canonical_query_string;
    (void)canonical_headers;
    (void)signed_headers;
    (void)payload_hash;
    return "";
}

std::string S3Uploader::build_string_to_sign(const std::string& amz_datetime,
                                             const std::string& date,
                                             const std::string& region,
                                             const std::string& service,
                                             const std::string& canonical_request_hash) {
    // TODO: implement SigV4 string-to-sign.
    (void)amz_datetime;
    (void)date;
    (void)region;
    (void)service;
    (void)canonical_request_hash;
    return "";
}

std::string S3Uploader::derive_signing_key(const std::string& secret_key,
                                           const std::string& date,
                                           const std::string& region,
                                           const std::string& service) {
    // TODO: implement SigV4 signing key derivation.
    (void)secret_key;
    (void)date;
    (void)region;
    (void)service;
    return "";
}

std::string S3Uploader::build_authorization_header(const std::string& access_key,
                                                   const std::string& date,
                                                   const std::string& region,
                                                   const std::string& service,
                                                   const std::string& signed_headers,
                                                   const std::string& signature) {
    // TODO: implement SigV4 Authorization header.
    (void)access_key;
    (void)date;
    (void)region;
    (void)service;
    (void)signed_headers;
    (void)signature;
    return "";
}

bool S3Uploader::perform_put(const std::string& bucket,
                             const std::string& object_key,
                             const std::string& payload,
                             const std::string& payload_hash) {
    // TODO: implement actual HTTP PUT using libcurl.
    (void)bucket;
    (void)object_key;
    (void)payload;
    (void)payload_hash;
    return false;
}