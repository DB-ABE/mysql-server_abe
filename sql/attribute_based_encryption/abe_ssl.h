#ifndef SEC_ABE_SSL_H
#define SEC_ABE_SSL_H

#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/rsa.h"      
#include "openssl/crypto.h"
#include "cJSON.h"

struct AbeSslConfig
{
    char *ca_cert_file = NULL;
    char *db_cert_file = NULL;
    char *db_key_file = NULL;
    char *kms_cert_file = NULL;
    char *kms_ip = NULL;
    ulong kms_port;
    char *uuid = NULL;

    ~AbeSslConfig();
    void set_default_file();
    void set_kms_addr();
};

typedef struct _AbeInfoData
{
    char *user_name = NULL;
    char *attribute = NULL;
    char *db_signature = NULL;
    char *db_signature_type = NULL;
    char *abe_key = NULL;
    char *kms_signature = NULL;
    char *kms_signature_type = NULL;
    ~_AbeInfoData();
    bool checkResult() const;
} AbeInfo, *pAbeInfo;

struct Abe_ssl
{
public:
    static constexpr int MAX_MSG_LENGTH = 200;
    static constexpr int BODY_LENGTH_BYTE = 2;
    static constexpr int BODY_LENGTH_BYTE_LENGTH = BODY_LENGTH_BYTE * 2;
    enum enum_event_type {ENUM_EVENT_USER_REGISTRATION, ENUM_EVENT_UNKOWN};
    enum enum_response_code {ENUM_RESPONSE_SUCCESS, ENUM_RESPONSE_USER_PK_NOT_FOUND, ENUM_RESPONSE_UNKOWN};

    //读取配置信息，建立SSL连接，完成注册流程后将信息写入abe_info中
    bool generateABEInfo(AbeInfo &abe_info);

private:
    //构造json数据包并发送
    bool process_user_registration_request(SSL *ssl, AbeSslConfig &config, AbeInfo &abe_info);

    bool set_user_registration_request(cJSON *cjson, AbeSslConfig &config, const AbeInfo &abe_info);
    void send_user_registration_request(SSL *ssl, const char *msg, size_t msg_length);
    void set_user_registration_uuid(cJSON *cjson, AbeSslConfig &config);
    bool set_user_registration_db_signature(cJSON *cjson, const char *db_key_file, const AbeInfo &abe_info);
    bool set_abe_info_from_request_json(cJSON *cjson, AbeInfo &abe_info);

    //接收KMS返回的数据包并解析
    bool process_user_registration_response(SSL *ssl, const AbeSslConfig &config, AbeInfo &abe_info);

    char *recv_user_registration_response(SSL *ssl);
    bool parse_user_registration_response(const char *json_str, const char *uuid_str, AbeInfo &abe_info);
    bool verify_kms_signature(const AbeInfo &abe_info, const char *kms_cert_file);

    
    int create_socket(const AbeSslConfig &config);
    SSL_CTX *init_ssl_context(const AbeSslConfig &config);
    SSL *create_ssl_connection(SSL_CTX *ssl_ctx, int sockfd);
    void read_msg(SSL *ssl, char *msg, size_t msg_length);
    void write_msg(SSL *ssl, const char *msg, size_t msg_length);
};

#endif // SEC_ABE_SSL_H