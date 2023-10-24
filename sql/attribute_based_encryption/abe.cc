#include "abe.h"
#include "abe_ssl.h"
#include <string>
#include <string.h>
// #include "sql/table.h"

std::string addAbeKeyCommand(std::string namehost, const AbeInfo abe_info)
{
    // TABLE_LIST tables("mysql", "abe_user_key", TL_WRITE);
    std::string command = "insert into mysql.abe_user_key(owner,encrypted_key,sig_db,sig_db_type,sig_kms,sig_kms_type) values('";
    command += namehost;
    command += "','";
    command += abe_info->abe_key;
    command += "','";
    command += abe_info->db_signature;
    command += "','";
    command += abe_info->db_signature_type;
    command += "','";
    command += abe_info->kms_signature;
    command += "','";
    command += abe_info->kms_signature_type;
    command += "')";
    return command;

}

std::string initAbeData(std::string namehost, std::string abeAttribute)
{
    AbeInfo abe_info = (AbeInfo)malloc(sizeof(AbeInfoData));
    Abe_ssl abe_ssl;
    abe_info->user_name = strdup(namehost.c_str());
    abe_info->attribute = strdup(abeAttribute.c_str());
    abe_ssl.generateABEInfo(abe_info);

    std::string command = addAbeKeyCommand(namehost, abe_info);
    free(abe_info->user_name);
    free(abe_info->attribute);
    free(abe_info);
    return command;
}