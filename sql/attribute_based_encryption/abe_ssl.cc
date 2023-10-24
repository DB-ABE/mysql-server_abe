#include "cJSON.h"
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <arpa/inet.h>
#include <string>

#include "sql/mysqld.h"
#include "mysqld_error.h"
#include "mysql/components/services/log_builtins.h"

#include "abe_ssl.h"
#include "base64.h"
#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/rsa.h"      
#include "openssl/crypto.h"

AbeSslConfig::~AbeSslConfig()
{
    free(ca_cert_file);
    free(db_cert_file);
    free(db_key_file);
    free(kms_cert_file);
    free(kms_ip);
    free(uuid);
}

void AbeSslConfig::set_ca_cert_file()
{
    ca_cert_file = strdup(abe_ca_cert_file);
}

void AbeSslConfig::set_db_cert_file()
{
    db_cert_file = strdup(abe_db_cert_file);
}

void AbeSslConfig::set_db_key_file()
{
    db_key_file = strdup(abe_db_key_file);
}

void AbeSslConfig::set_kms_cert_file()
{
    kms_cert_file = strdup(abe_kms_cert_file);
}

void AbeSslConfig::set_default_file()
{
    set_ca_cert_file();
    set_db_cert_file();
    set_db_key_file();
    set_kms_cert_file();
}

void AbeSslConfig::set_kms_addr()
{
    kms_ip = strdup(abe_kms_ip);
    kms_port = abe_kms_port;
}

int Abe_ssl::create_socket(const AbeSslConfig &config) {
    int sockfd = -1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to create socket");
    }

    sockaddr_in kms_addr;
    kms_addr.sin_family = AF_INET;
    kms_addr.sin_port = htons(config.kms_port);
    inet_pton(AF_INET, config.kms_ip, &kms_addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr*)(&kms_addr), sizeof(kms_addr)) == -1) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to connect to kms");
    }

    return sockfd;
}

SSL_CTX *Abe_ssl::init_ssl_context(const AbeSslConfig &config)
{
    SSL_CTX *ssl_ctx = NULL;

    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if(ssl_ctx == NULL) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to create ssl ctx for abe");
    }

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);   
    
    if (SSL_CTX_load_verify_locations(ssl_ctx, config.ca_cert_file, NULL) <= 0) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to use ca certificate file");
    }

    if (SSL_CTX_use_certificate_file(ssl_ctx, config.db_cert_file, SSL_FILETYPE_PEM) <= 0) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to use db certificate file");
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, config.db_key_file, SSL_FILETYPE_PEM) <= 0) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to use db private key file");
    }

    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Certificate does not match private key");
    }

    SSL_CTX_set_cipher_list(ssl_ctx, "ECDHE-RSA-AES256-SHA");
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

    return ssl_ctx;
}

SSL *Abe_ssl::create_ssl_connection(SSL_CTX *ssl_ctx, int sockfd) {
    SSL *ssl = NULL;

    ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sockfd);
    
    if (SSL_connect(ssl) != 1) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to establish SSL connection");
    }
    
    return ssl;
}

void Abe_ssl::read_msg(SSL *ssl, char *msg, size_t msg_length)
{
    size_t byte_cnt = 0;
    size_t current_byte_cnt = 0;
    while (byte_cnt < msg_length) {
        current_byte_cnt = SSL_read(ssl, msg + byte_cnt, msg_length - byte_cnt);
        byte_cnt += current_byte_cnt;
    }
}

void Abe_ssl::write_msg(SSL *ssl, const char *msg, size_t msg_length)
{
    size_t byte_cnt = 0;
    size_t current_byte_cnt = 0;
    while (byte_cnt < msg_length) {
        current_byte_cnt = SSL_write(ssl, msg + byte_cnt, msg_length - byte_cnt);
        byte_cnt += current_byte_cnt;
    }
}

void Abe_ssl::set_user_registration_uuid(cJSON *cjson, AbeSslConfig &config)
{
    boost::uuids::uuid uuid;
    std::string uuid_str;

    uuid = boost::uuids::random_generator()();
    uuid_str = boost::uuids::to_string(uuid);

    cJSON_AddStringToObject(cjson, "uuid", uuid_str.c_str());

    config.uuid = strdup(uuid_str.c_str());
}

void Abe_ssl::set_user_registration_db_signature(cJSON *cjson, const char *db_key_file, const AbeInfo abe_info)
{
    FILE *private_key_file = NULL;
    RSA* rsa = NULL;
    std::string buf;
    unsigned char* db_signature = NULL;
    unsigned int db_signature_length = 0;
    char* db_signature_b64 = NULL;
    unsigned int db_signature_b64_length = 0;
    static unsigned char hash_msg[SHA256_DIGEST_LENGTH];

    private_key_file = fopen(db_key_file, "r");
    if (private_key_file == NULL) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to use private key file");
    }

    rsa = PEM_read_RSAPrivateKey(private_key_file, NULL, NULL, NULL);
    if (rsa == NULL) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to read private key file");
    }

    buf = std::string(abe_info->user_name) + std::string(abe_info->attribute);
    
    SHA256((unsigned char*)buf.c_str(), buf.size(), hash_msg);
    db_signature = (unsigned char*)malloc(RSA_size(rsa));

    if (RSA_sign(NID_sha256, hash_msg, SHA256_DIGEST_LENGTH, 
        db_signature, &db_signature_length, rsa) != 1) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "RSA Signature Failed");
    }

    db_signature_b64 = (char*)malloc(base64_utils::b64_enc_len(db_signature_length) + 1);
    db_signature_b64_length = base64_utils::b64_encode((char*)db_signature, db_signature_length, db_signature_b64);
    db_signature_b64[db_signature_b64_length] = '\0';

    cJSON_AddStringToObject(cjson, "dbSignature", db_signature_b64);
    cJSON_AddStringToObject(cjson, "dbSignatureType", "RSA");

    free(db_signature_b64);
    free(db_signature);
    RSA_free(rsa);
    fclose(private_key_file);
}

void Abe_ssl::set_user_registration_request(cJSON *cjson, AbeSslConfig &config, const AbeInfo abe_info)
{
    cJSON_AddNumberToObject(cjson, "type", ENUM_EVENT_USER_REGISTRATION);
    set_user_registration_uuid(cjson, config);
    cJSON_AddStringToObject(cjson, "userName", abe_info->user_name);
    cJSON_AddStringToObject(cjson, "attribute", abe_info->attribute);
    set_user_registration_db_signature(cjson, config.db_key_file, abe_info);
}

void Abe_ssl::send_user_registration_request(SSL *ssl, const char *msg, size_t msg_length)
{
    static char buf[BODY_LENGTH_BYTE_LENGTH + 1];

    snprintf(buf, BODY_LENGTH_BYTE_LENGTH + 1, "%04zx", msg_length);

    write_msg(ssl, buf, BODY_LENGTH_BYTE_LENGTH);
    write_msg(ssl, msg, msg_length);
}

void Abe_ssl::set_abe_info_from_request_json(cJSON *cjson, AbeInfo abe_info)
{
    cJSON *db_signature = NULL;
    cJSON *db_signature_type = NULL;

    db_signature = cJSON_GetObjectItem(cjson, "dbSignature");
    if (!cJSON_IsObject(db_signature)) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to parse json");
    }
    abe_info->db_signature = strdup(db_signature->valuestring);

    db_signature_type = cJSON_GetObjectItem(cjson, "dbSignatureType");
    if (!cJSON_IsObject(db_signature_type)) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to parse json");
    }
    abe_info->db_signature_type = strdup(db_signature_type->valuestring);
}

void Abe_ssl::process_user_registration_request(SSL *ssl, AbeSslConfig &config, AbeInfo abe_info)
{
    char *json_str = NULL;
    cJSON *request_json = NULL;
    
    request_json = cJSON_CreateObject();
    set_user_registration_request(request_json, config, abe_info);

    set_abe_info_from_request_json(request_json, abe_info);

    json_str = cJSON_PrintUnformatted(request_json);
    send_user_registration_request(ssl, json_str, strlen(json_str));

    cJSON_Delete(request_json);
    free(json_str);
}

char *Abe_ssl::recv_user_registration_response(SSL *ssl)
{
    char *msg = NULL;
    size_t msg_length = 0;
    static char buf[BODY_LENGTH_BYTE_LENGTH + 1];

    read_msg(ssl, buf, BODY_LENGTH_BYTE_LENGTH);
    buf[BODY_LENGTH_BYTE_LENGTH] = '\0';
    msg_length = strtoul(buf, NULL, 16);

    msg = (char*)malloc(msg_length + 1);
    read_msg(ssl, msg, msg_length);
    msg[msg_length] = '\0';

    return msg;
}

void Abe_ssl::parse_user_registration_response(const char *json_str, const char *uuid_str, AbeInfo abe_info)
{
    cJSON *response_json = NULL;
    cJSON* code = NULL;
    cJSON* msg = NULL;
    cJSON* data = NULL;
    cJSON* uuid = NULL;
    cJSON* abe_key = NULL;
    cJSON* kms_signature = NULL;
    cJSON* kms_signature_type = NULL;

    response_json = cJSON_Parse(json_str);
    if (response_json == NULL) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to parse json from kms response");
    }

    code = cJSON_GetObjectItem(response_json, "code");
    msg = cJSON_GetObjectItem(response_json, "msg");
    data = cJSON_GetObjectItem(response_json, "data");
    if (!cJSON_IsNumber(code) || !cJSON_IsString(msg) || !cJSON_IsObject(data)) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to parse json from kms response");
    }

    uuid = cJSON_GetObjectItem(data, "uuid");
    if (!cJSON_IsString(uuid)) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to parse json from kms response");
    }

    if (strcmp(uuid->valuestring, uuid_str) != 0) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Inconsistent uuid between request and response");
    }

    if (code->valueint != ENUM_RESPONSE_SUCCESS) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Response error from kms.");
    }

    abe_key = cJSON_GetObjectItem(data, "abeKey");
    kms_signature = cJSON_GetObjectItem(data, "kmsSignature");
    kms_signature_type = cJSON_GetObjectItem(data, "kmsSignatureType");
    if (!cJSON_IsString(abe_key) || !cJSON_IsString(kms_signature) || !cJSON_IsString(kms_signature_type)) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to parse json from kms response");
    }
    
    abe_info->abe_key = strdup(abe_key->valuestring);
    abe_info->kms_signature = strdup(kms_signature->valuestring);
    abe_info->kms_signature_type = strdup(kms_signature_type->valuestring);

    cJSON_Delete(response_json);
}

void Abe_ssl::verify_kms_signature(const AbeInfo abe_info, const char *kms_cert_file)
{
    FILE* cert_file = NULL;
    X509* x509_cert = NULL;
    EVP_PKEY* evp_key = NULL;
    RSA* rsa = NULL;
    unsigned char *abe_key = NULL;
    unsigned char *kms_signature = NULL;
    char *abe_key_b64 = NULL;
    char *kms_signature_b64 = NULL;
    unsigned int abe_key_length = 0;
    unsigned int kms_signature_length = 0;
    unsigned int abe_key_b64_length = 0;
    unsigned int kms_signature_b64_length = 0;
    static unsigned char hash_msg[SHA256_DIGEST_LENGTH];

    if (strcmp(abe_info->kms_signature_type, "RSA") != 0) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "only support for RSA signatures yet");
    }

    cert_file = fopen(kms_cert_file, "r");
    if (cert_file == NULL) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to open kms cert file");
    }

    x509_cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if (x509_cert == NULL) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to read kms cert file");
    }

    evp_key = X509_get_pubkey(x509_cert);
    if (evp_key == NULL) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to get publib key from kms cert file");
    }

    rsa = EVP_PKEY_get1_RSA(evp_key);
    if (rsa == NULL) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "Failed to get rsa publib key from kms cert file");
    }

    kms_signature_b64 = abe_info->kms_signature;
    kms_signature_b64_length = strlen(kms_signature_b64);
    kms_signature = (unsigned char*)malloc(base64_utils::b64_dec_len(kms_signature_b64_length));
    kms_signature_length = base64_utils::b64_decode(kms_signature_b64, kms_signature_b64_length, (char*)kms_signature);

    abe_key_b64 = abe_info->abe_key;
    abe_key_b64_length = strlen(abe_key_b64);
    abe_key = (unsigned char*)malloc(base64_utils::b64_dec_len(abe_key_b64_length));
    abe_key_length = base64_utils::b64_decode(abe_key_b64, abe_key_b64_length, (char*)abe_key);

    SHA256(abe_key, abe_key_length, hash_msg);

    if (RSA_verify(NID_sha256, hash_msg, SHA256_DIGEST_LENGTH, 
        kms_signature, kms_signature_length, rsa) != 1) {
        LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, "kms signature verification failed");
    }

    free(abe_key);
    free(kms_signature);
    RSA_free(rsa);
    EVP_PKEY_free(evp_key);
    X509_free(x509_cert);
    fclose(cert_file);
}

void Abe_ssl::process_user_registration_response(SSL *ssl, const AbeSslConfig &config, AbeInfo abe_info)
{
    char *json_str = NULL;

    json_str = recv_user_registration_response(ssl);

    parse_user_registration_response(json_str, config.uuid, abe_info);

    verify_kms_signature(abe_info, config.kms_cert_file);
    
    free(json_str);
}

void Abe_ssl::generateABEInfo(AbeInfo abe_info)
{
    int sockfd = -1;
    SSL_CTX* ssl_ctx = NULL;
    SSL* ssl = NULL;
    AbeSslConfig config;
    
    config.set_kms_addr();
    config.set_default_file();

    sockfd = create_socket(config);
    ssl_ctx = init_ssl_context(config);
    ssl = create_ssl_connection(ssl_ctx, sockfd);

    process_user_registration_request(ssl, config, abe_info);
    process_user_registration_response(ssl, config, abe_info);
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(sockfd);
}