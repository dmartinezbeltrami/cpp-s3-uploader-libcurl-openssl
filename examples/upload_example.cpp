#include "s3_uploader.h"

int main() {
    S3Config cfg{
        "ACCESS_KEY",
        "SECRET_KEY",
        "us-east-1",
        "https://s3.amazonaws.com"
    };

    S3Uploader uploader(cfg);
    // Not implemented yet:
    // bool ok = uploader.upload_file("my-bucket", "path/in/bucket/file.txt", "local_file.txt");
    return 0;
}