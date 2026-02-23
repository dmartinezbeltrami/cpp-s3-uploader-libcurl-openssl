#pragma once

#include <string>

struct S3Config {
    std::string access_key;
    std::string secret_key;
    std::string region;
    std::string endpoint;   // e.g. "https://s3.amazonaws.com" or DO Spaces
};

class S3Uploader {
public:
    explicit S3Uploader(S3Config config);

    // Uploads a local file to the given bucket + object key.
    // Returns true on success, false on failure.
    bool upload_file(const std::string& bucket,
                     const std::string& object_key,
                     const std::string& local_path);

private:
    S3Config config_;

    // later:
    // std::string build_authorization_header(...);
    // std::string build_canonical_request(...);
    // etc.
};