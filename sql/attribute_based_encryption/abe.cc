#include "abe.h"
#include "abe_ssl.h"
#include <string>
#include <string.h>
// #include "sql/table.h"

bool addAbeKeyCommand(std::string &command, const std::string namehost, const AbeInfo &abe_info)
{
    if(!abe_info.checkResult())
        return false;

    command = "insert into mysql.abe_user_key(owner,encrypted_key,sig_db,sig_db_type,sig_kms,sig_kms_type) values('";
    command += namehost;
    command += "','";
    command += abe_info.abe_key;
    command += "','";
    command += abe_info.db_signature;
    command += "','";
    command += abe_info.db_signature_type;
    command += "','";
    command += abe_info.kms_signature;
    command += "','";
    command += abe_info.kms_signature_type;
    command += "')";
    return true;

}

bool initAbeData(std::string &command, const std::string namehost, const std::string abeAttribute)
{
    AbeInfo abe_info;
    Abe_ssl abe_ssl;
    abe_info.user_name = strdup(namehost.c_str());
    abe_info.attribute = strdup(abeAttribute.c_str());
    if(!abe_ssl.generateABEInfo(abe_info))
        return false;

    if(!addAbeKeyCommand(command, namehost, abe_info))
        return false;
    return true;;
}