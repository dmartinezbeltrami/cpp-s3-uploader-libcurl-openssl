#include "s3_uploader.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <iomanip>
#include <sstream>
#include <utility>

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
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // Compute SHA256 of the input data
    SHA256(reinterpret_cast<const unsigned char*>(data.data()),
           data.size(),
           hash);

    // Convert to lowercase hex string
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char byte : hash) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

std::vector<unsigned char> S3Uploader::hmac_sha256(const std::string& key,
                                                   const std::string& message) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len = 0;

    const EVP_MD* md = EVP_sha256();

    HMAC(md,
         reinterpret_cast<const unsigned char*>(key.data()),
         static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(message.data()),
         message.size(),
         result,
         &result_len);

    return std::vector<unsigned char>(result, result + result_len);
}

std::string S3Uploader::hmac_sha256_hex(const std::string& key,
                                        const std::string& message) {
    auto bytes = hmac_sha256(key, message);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

std::string S3Uploader::build_canonical_request(const std::string& http_method,
                                                const std::string& canonical_uri,
                                                const std::string& canonical_query_string,
                                                const std::string& canonical_headers,
                                                const std::string& signed_headers,
                                                const std::string& payload_hash) {
    // Canonical request format (SigV4):
    //
    // CanonicalRequest =
    //   HTTPMethod + '\n' +
    //   CanonicalURI + '\n' +
    //   CanonicalQueryString + '\n' +
    //   CanonicalHeaders + '\n' +
    //   SignedHeaders + '\n' +
    //   PayloadHash
    //
    // Note: canonical_headers should already include the final '\n'.

    std::string canonical_request;
    canonical_request.reserve(256); // rough guess to avoid reallocs

    canonical_request.append(http_method).append("\n");
    canonical_request.append(canonical_uri).append("\n");
    canonical_request.append(canonical_query_string).append("\n");
    canonical_request.append(canonical_headers).append("\n");
    canonical_request.append(signed_headers).append("\n");
    canonical_request.append(payload_hash);

    return canonical_request;
}

std::string S3Uploader::build_string_to_sign(const std::string& amz_datetime,
                                             const std::string& date,
                                             const std::string& region,
                                             const std::string& service,
                                             const std::string& canonical_request_hash) {
    // StringToSign format (SigV4):
    //
    // StringToSign =
    //   Algorithm + '\n' +
    //   RequestDateTime + '\n' +
    //   CredentialScope + '\n' +
    //   HexEncode(Hash(CanonicalRequest))
    //
    // Here we assume canonical_request_hash is already HexEncode(Hash(CanonicalRequest)).
    //
    // Algorithm is always "AWS4-HMAC-SHA256".
    //
    // CredentialScope = date + "/" + region + "/" + service + "/aws4_request"

    const std::string algorithm = "AWS4-HMAC-SHA256";
    const std::string credential_scope =
        date + "/" + region + "/" + service + "/aws4_request";

    std::string string_to_sign;
    string_to_sign.reserve(256);

    string_to_sign.append(algorithm).append("\n");
    string_to_sign.append(amz_datetime).append("\n");
    string_to_sign.append(credential_scope).append("\n");
    string_to_sign.append(canonical_request_hash);

    return string_to_sign;
}

std::string S3Uploader::derive_signing_key(const std::string& secret_key,
                                           const std::string& date,
                                           const std::string& region,
                                           const std::string& service) {
    // SigV4 signing key derivation:
    //
    // kDate    = HMAC("AWS4" + secret_key, date)
    // kRegion  = HMAC(kDate, region)
    // kService = HMAC(kRegion, service)
    // kSigning = HMAC(kService, "aws4_request")
    //
    // We return kSigning as a binary string (not hex).

    const std::string k_secret = "AWS4" + secret_key;

    // kDate
    auto k_date_bytes = hmac_sha256(k_secret, date);
    std::string k_date(reinterpret_cast<const char*>(k_date_bytes.data()),
                       k_date_bytes.size());

    // kRegion
    auto k_region_bytes = hmac_sha256(k_date, region);
    std::string k_region(reinterpret_cast<const char*>(k_region_bytes.data()),
                         k_region_bytes.size());

    // kService
    auto k_service_bytes = hmac_sha256(k_region, service);
    std::string k_service(reinterpret_cast<const char*>(k_service_bytes.data()),
                          k_service_bytes.size());

    // kSigning
    auto k_signing_bytes = hmac_sha256(k_service, "aws4_request");
    std::string k_signing(reinterpret_cast<const char*>(k_signing_bytes.data()),
                          k_signing_bytes.size());

    return k_signing;
}

std::string S3Uploader::build_authorization_header(const std::string& access_key,
                                                   const std::string& date,
                                                   const std::string& region,
                                                   const std::string& service,
                                                   const std::string& signed_headers,
                                                   const std::string& signature) {
    // Authorization header format:
    //
    // Authorization: AWS4-HMAC-SHA256
    //   Credential=access_key/credential_scope,
    //   SignedHeaders=signed_headers,
    //   Signature=signature
    //
    // We only return the value part, not the "Authorization:" key.

    const std::string credential_scope =
        date + "/" + region + "/" + service + "/aws4_request";

    std::ostringstream oss;
    oss << "AWS4-HMAC-SHA256 "
        << "Credential=" << access_key << "/" << credential_scope
        << ", SignedHeaders=" << signed_headers
        << ", Signature=" << signature;

    return oss.str();
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