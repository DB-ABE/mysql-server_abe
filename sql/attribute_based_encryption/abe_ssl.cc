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

#define ABE_ERROR(errmsg) LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, (errmsg)); \
                            my_error(ER_ABE_DB_ERROR, MYF(0), (errmsg));\

#define ABE_KMS_ERROR(errmsg) LogErr(ERROR_LEVEL, ER_ABE_SYSTEM, (errmsg)); \
                            my_error(ER_ABE_KMS_ERROR, MYF(0), (errmsg));\

AbeSslConfig::~AbeSslConfig()
{
    if(ca_cert_file != NULL)    free(ca_cert_file);
    if(db_cert_file != NULL)    free(db_cert_file);
    if(db_key_file != NULL)     free(db_key_file);
    if(kms_cert_file != NULL)   free(kms_cert_file);
    if(kms_ip != NULL)          free(kms_ip);
    if(uuid != NULL)            free(uuid);
}

void AbeSslConfig::set_default_file()
{
    ca_cert_file = NULL;
    db_cert_file = NULL;
    db_key_file = NULL;
    kms_cert_file = NULL;
    if(strlen(abe_ca_cert_file) != 0 )
        ca_cert_file = strdup(abe_ca_cert_file);
    if(strlen(abe_db_cert_file) != 0 )
        db_cert_file = strdup(abe_db_cert_file);
    if(strlen(abe_db_key_file) != 0 )
        db_key_file = strdup(abe_db_key_file);
    if(strlen(abe_kms_cert_file) != 0 )
        kms_cert_file = strdup(abe_kms_cert_file);
}

void AbeSslConfig::set_kms_addr()
{
    kms_ip = NULL;
    if(strlen(abe_kms_ip) != 0)
        kms_ip = strdup(abe_kms_ip);
    kms_port = abe_kms_port;
}

_AbeInfoData::~_AbeInfoData(){
    if(user_name != NULL)       free(user_name);
    if(attribute != NULL)       free(attribute);
    if(db_signature != NULL)    free(db_signature);
    if(db_signature_type != NULL)    free(db_signature_type);
    if(abe_key != NULL)         free(abe_key);
    if(kms_signature != NULL)   free(kms_signature);
    if(kms_signature_type != NULL)    free(kms_signature_type);
}

//检查是否成功获取到了abe_key
bool _AbeInfoData::checkResult() const {
    if(abe_key != NULL && db_signature != NULL && db_signature_type != NULL
                        && kms_signature != NULL && kms_signature_type != NULL){
        return true;
    }
    return false;
}


//正常返回socket，否则返回-1
int Abe_ssl::create_socket(const AbeSslConfig &config) {
    int sockfd = -1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        ABE_ERROR("Failed to create socket");
        return -1;
    }

    sockaddr_in kms_addr;
    kms_addr.sin_family = AF_INET;
    kms_addr.sin_port = htons(config.kms_port);
    inet_pton(AF_INET, config.kms_ip, &kms_addr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr*)(&kms_addr), sizeof(kms_addr)) == -1) {
        ABE_ERROR("Failed to connect to kms");
        return -1;
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
        ABE_ERROR("Failed to create ssl ctx for abe");
        return NULL;
    }

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);   
    
    if (SSL_CTX_load_verify_locations(ssl_ctx, config.ca_cert_file, NULL) <= 0) {
        ABE_ERROR("Failed to use ca certificate file");
        return NULL;
    }

    if (SSL_CTX_use_certificate_file(ssl_ctx, config.db_cert_file, SSL_FILETYPE_PEM) <= 0) {
        ABE_ERROR("Failed to use db certificate file");
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, config.db_key_file, SSL_FILETYPE_PEM) <= 0) {
        ABE_ERROR("Failed to use db private key file");
        return NULL;
    }

    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        ABE_ERROR("Certificate does not match private key");
        return NULL;
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
        ABE_ERROR("Failed to establish SSL connection");
        return NULL;
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

bool Abe_ssl::set_user_registration_db_signature(cJSON *cjson, const char *db_key_file, const AbeInfo &abe_info)
{
    FILE *private_key_file = NULL;
    RSA* rsa = NULL;
    std::string buf;
    unsigned char* db_signature = NULL;
    unsigned int db_signature_length = 0;
    char* db_signature_b64 = NULL;
    unsigned int db_signature_b64_length = 0;
    static unsigned char hash_msg[SHA512_DIGEST_LENGTH];

    private_key_file = fopen(db_key_file, "r");
    if (private_key_file == NULL) {
        ABE_ERROR("Failed to use private key file");
        return false;
    }

    rsa = PEM_read_RSAPrivateKey(private_key_file, NULL, NULL, NULL);
    if (rsa == NULL) {
        ABE_ERROR("Failed to read private key file");
        fclose(private_key_file);
        return false;
    }

    buf = std::string(abe_info.user_name) + std::string(abe_info.attribute);
    
    SHA512((const unsigned char*)buf.c_str(), buf.size(), hash_msg);
    db_signature = (unsigned char*)malloc(RSA_size(rsa));

    if (RSA_sign(NID_sha512, hash_msg, SHA512_DIGEST_LENGTH, 
                db_signature, &db_signature_length, rsa) != 1) {
        ABE_ERROR("RSA Signature Failed");
        free(db_signature);
        RSA_free(rsa);
        fclose(private_key_file);
        return false;
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
    return true;
}

bool Abe_ssl::set_user_registration_request(cJSON *cjson, AbeSslConfig &config, const AbeInfo &abe_info)
{
    cJSON_AddNumberToObject(cjson, "type", ENUM_EVENT_USER_REGISTRATION);
    set_user_registration_uuid(cjson, config);
    cJSON_AddStringToObject(cjson, "userName", abe_info.user_name);
    cJSON_AddStringToObject(cjson, "attribute", abe_info.attribute);
    return set_user_registration_db_signature(cjson, config.db_key_file, abe_info);
}

void Abe_ssl::send_user_registration_request(SSL *ssl, const char *msg, size_t msg_length)
{
    static char buf[BODY_LENGTH_BYTE_LENGTH + 1];

    snprintf(buf, BODY_LENGTH_BYTE_LENGTH + 1, "%04zx", msg_length);

    write_msg(ssl, buf, BODY_LENGTH_BYTE_LENGTH);
    write_msg(ssl, msg, msg_length);
}

bool Abe_ssl::set_abe_info_from_request_json(cJSON *cjson, AbeInfo &abe_info)
{
    cJSON *db_signature = NULL;
    cJSON *db_signature_type = NULL;

    db_signature = cJSON_GetObjectItem(cjson, "dbSignature");
    if (db_signature == NULL) {
        ABE_ERROR("Failed to parse json(dbSignature)");
        return false;
    }
    abe_info.db_signature = strdup(db_signature->valuestring);

    db_signature_type = cJSON_GetObjectItem(cjson, "dbSignatureType");
    if (db_signature_type == NULL) {
        ABE_ERROR("Failed to parse json(dbSignatureType)");
        return false;
    }
    abe_info.db_signature_type = strdup(db_signature_type->valuestring);
    return true;
}

bool Abe_ssl::process_user_registration_request(SSL *ssl, AbeSslConfig &config, AbeInfo &abe_info)
{
    char *json_str = NULL;
    cJSON *request_json = NULL;
    
    request_json = cJSON_CreateObject();

    if( !(set_user_registration_request(request_json, config, abe_info)
        && set_abe_info_from_request_json(request_json, abe_info))){
            cJSON_Delete(request_json);
            return false;
        }

    json_str = cJSON_PrintUnformatted(request_json);
    send_user_registration_request(ssl, json_str, strlen(json_str));

    cJSON_Delete(request_json);
    free(json_str);
    return true;
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

bool Abe_ssl::parse_user_registration_response(const char *json_str, const char *uuid_str, AbeInfo &abe_info)
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
        ABE_KMS_ERROR("Failed to parse json from kms response");
        return false;
    }

    code = cJSON_GetObjectItem(response_json, "code");
    msg = cJSON_GetObjectItem(response_json, "msg");
    data = cJSON_GetObjectItem(response_json, "data");
    if (!cJSON_IsNumber(code) || !cJSON_IsString(msg) || !cJSON_IsObject(data)) {
        ABE_KMS_ERROR("Failed to parse json from kms response");
        return false;
    }

    uuid = cJSON_GetObjectItem(data, "uuid");
    if (!cJSON_IsString(uuid)) {
        ABE_KMS_ERROR("Failed to parse json from kms response");
        cJSON_Delete(response_json);
        return false;
    }

    if (strcmp(uuid->valuestring, uuid_str) != 0) {
        ABE_KMS_ERROR("Inconsistent uuid between request and response");
        cJSON_Delete(response_json);
        return false;
    }

    if (code->valueint != ENUM_RESPONSE_SUCCESS) {
        std::string errmsg = std::string("Response error from kms(");
        errmsg += msg->valuestring + std::string(")");
        ABE_KMS_ERROR(errmsg.c_str());
        cJSON_Delete(response_json);
        return false;
    }

    abe_key = cJSON_GetObjectItem(data, "abeKey");
    kms_signature = cJSON_GetObjectItem(data, "kmsSignature");
    kms_signature_type = cJSON_GetObjectItem(data, "kmsSignatureType");
    if (!cJSON_IsString(abe_key) || !cJSON_IsString(kms_signature) || !cJSON_IsString(kms_signature_type)) {
        ABE_KMS_ERROR("Failed to parse json from kms response");
        cJSON_Delete(response_json);
        return false;
    }
    
    abe_info.abe_key = strdup(abe_key->valuestring);
    abe_info.kms_signature = strdup(kms_signature->valuestring);
    abe_info.kms_signature_type = strdup(kms_signature_type->valuestring);

    cJSON_Delete(response_json);
    return true;
}

bool Abe_ssl::verify_kms_signature(const AbeInfo &abe_info, const char *kms_cert_file)
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
    static unsigned char hash_msg[SHA512_DIGEST_LENGTH];

    if (strcmp(abe_info.kms_signature_type, "RSA") != 0) {
        ABE_ERROR("only support for RSA signatures yet");
        return false;
    }

    cert_file = fopen(kms_cert_file, "r");
    if (cert_file == NULL) {
        ABE_ERROR("Failed to open kms cert file");
        return false;
    }

    x509_cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if (x509_cert == NULL) {
        ABE_ERROR("Failed to read kms cert file");
        fclose(cert_file);
        return false;
    }

    evp_key = X509_get_pubkey(x509_cert);
    if (evp_key == NULL) {
        ABE_ERROR("Failed to get publib key from kms cert file");
        X509_free(x509_cert);
        fclose(cert_file);
        return false;
    }

    rsa = EVP_PKEY_get1_RSA(evp_key);
    if (rsa == NULL) {
        ABE_ERROR("Failed to get rsa publib key from kms cert file");
        EVP_PKEY_free(evp_key);
        X509_free(x509_cert);
        fclose(cert_file);
        return false;
    }

    kms_signature_b64 = abe_info.kms_signature;
    kms_signature_b64_length = strlen(kms_signature_b64);
    kms_signature = (unsigned char*)malloc(base64_utils::b64_dec_len(kms_signature_b64_length));
    kms_signature_length = base64_utils::b64_decode(kms_signature_b64, kms_signature_b64_length, (char*)kms_signature);

    abe_key_b64 = abe_info.abe_key;
    abe_key_b64_length = strlen(abe_key_b64);
    abe_key = (unsigned char*)malloc(base64_utils::b64_dec_len(abe_key_b64_length));
    abe_key_length = base64_utils::b64_decode(abe_key_b64, abe_key_b64_length, (char*)abe_key);

    SHA512(abe_key, abe_key_length, hash_msg);

    if (RSA_verify(NID_sha512, hash_msg, SHA512_DIGEST_LENGTH, 
                    kms_signature, kms_signature_length, rsa) != 1) {
        ABE_ERROR("kms signature verification failed");
        free(abe_key);
        free(kms_signature);
        RSA_free(rsa);
        EVP_PKEY_free(evp_key);
        X509_free(x509_cert);
        fclose(cert_file);
        return false;
    }

    free(abe_key);
    free(kms_signature);
    RSA_free(rsa);
    EVP_PKEY_free(evp_key);
    X509_free(x509_cert);
    fclose(cert_file);
    return true;
}

bool Abe_ssl::process_user_registration_response(SSL *ssl, const AbeSslConfig &config, AbeInfo &abe_info)
{
    char *json_str = NULL;

    json_str = recv_user_registration_response(ssl);

    if( !(parse_user_registration_response(json_str, config.uuid, abe_info)
        && verify_kms_signature(abe_info, config.kms_cert_file))){
            free(json_str);
            return false;
        }
    free(json_str);
    return true;
}

bool Abe_ssl::generateABEInfo(AbeInfo &abe_info)
{
    int sockfd = -1;
    SSL_CTX* ssl_ctx = NULL;
    SSL* ssl = NULL;
    AbeSslConfig config;
    
    config.set_kms_addr();
    config.set_default_file();

    sockfd = create_socket(config);
    if(sockfd == -1){
        return false;
    }

    ssl_ctx = init_ssl_context(config);
    if(ssl_ctx == NULL){
        close(sockfd);
        return false;
    }
    
    ssl = create_ssl_connection(ssl_ctx, sockfd);
    if(ssl == NULL){
        SSL_CTX_free(ssl_ctx);
        close(sockfd);
        return false;
    }

    //通信获取abe_key到abe_info中
    if( !(process_user_registration_request(ssl, config, abe_info)
        && process_user_registration_response(ssl, config, abe_info))){
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ssl_ctx);
            close(sockfd);
            return false;
        }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(sockfd);
    return true;
}