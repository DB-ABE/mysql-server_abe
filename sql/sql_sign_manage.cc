#include "sql_plugin.h"       // Includes my_global.h
#include "sql/auth/sql_acl.h" // fill_schema_*_privileges
#include "sql_select.h"       // For select_describe
#include "sql_base.h"         // close_tables_for_reopen
#include "sql_parse.h"        // check_access, check_table_access
#include "set_var.h"
#include "sql_list.h" /* List */
#include "handler.h"  /* enum_schema_tables */
#include "table.h"    /* enum_schema_table_state */
#include "sql_sign_manage.h"
#include "key.h"
#include "sql_class.h"
#include "mysql/com_data.h"
#include "protocol.h"
#include "log.h"
#include "sql/mysqld.h"
#include "sql_lex.h"
#include "mem_root_deque.h"
#include "lex_string.h"
#include "records.h"
#include <cstring>
#include <cstdio>
#include "protocol_classic.h"
#include "mysqld.h"
//#include "sql_cache.h"            /*query_cache.flush()*/
// #define LEX_STRING LEX_CSTRING
#include "my_dbug.h"
#include "sql/sql_class.h"
#include "sql/auth/auth_common.h"
#include "sql/auth/sql_auth_cache.h"

#include "records.h"

#include <iostream>
#include <fstream>
#include <regex>
#include <unordered_map>

class String;
struct TABLE_LIST;
struct LEX;
bool init = false;
// map<string, SIGN> db_user_map;
// map<string, SIGN> my_table_map;

extern vector<ATT> att_map;
extern vector<POLICY> policy_map;

#define CHECK_NULL(ptr) \
    if (ptr == NULL)    \
        return true;    \
//						else;  // xby20210625
#define EQUAL(LEX_STR1, LEX_STR2) ((LEX_STR1).length == (LEX_STR2).length && memcmp((LEX_STR1).str, (LEX_STR2).str, (LEX_STR1).length) == 0)

/*****************语法解析部分 start*************************/

//所有可能的指令类型
enum CommandType {
    BEGIN,

    CREATE_DOMAIN,
    CREATE_DOMAIN_RELATION,
    GRANT_DOMAIN,
    DROP_DOMAIN,
    DROP_DOMAIN_RELATION,
    SHOW_DOMAINS,
    SHOW_DOMAIN_RELATIONS,
    SHOW_USER_OR_DB_DOMAIN,
    SHOW_TABLE_DOMAIN,

    CREATE_LEVEL,
    CREATE_LEVEL_RELATION,
    GRANT_LEVEL,
    DROP_LEVEL,
    DROP_LEVEL_RELATION,
    SHOW_LEVELS,
    SHOW_LEVEL_RELATIONS,
    SHOW_USER_OR_DB_LEVEL,
    SHOW_TABLE_LEVEL,

    CREATE_ATTRIBUTE,
    GRANT_ATTRIBUTE,
    REVOKE_ATTRIBUTE,
    DROP_ATTRIBUTE,
    SHOW_ATTRIBUTES,
    SHOW_ATTRIBUTES_MANAGER,

    CREATE_POLICY,
    DROP_POLICY,
    SHOW_POLICIES,
    ENABLE_POLICY,
    DISABLE_POLICY,
    CREATE_USER_AND_ATT,
    GRANT_ABE_ATT,

    END
};
class SqlParser
{
   private:
    // SQL语句的信息，正则表达式和参数个数
    struct SqlInfo {
        string regex_expression;
        int arguments_number;
    };

    //初始化map，不需要有序，所以使用unordered_map
    std::unordered_map<int, SqlInfo> mp;
    string target;
    void initMap()
    {
        string CREATE = "create";
        string DROP = "drop";
        string ALTER = "alter";
        string REVOKE = "revoke";
        string SHOW = "show";
        string GRANT = "grant";
        string TO = "to";
        string ON = "on";
        string IN = "in";
        string FROM = "from";
        string ENABLE = "enable";
        string DISABLE = "disable";

        string ABE = "abe";
        string USER = "user";
        string IDENTIFIED = "identified";
        string BY = "by";
        string ABAC = "abac";
        string DOMAIN = "domain";
        string DOMAINS = "domains";
        string LEVEL = "level";
        string LEVELS = "levels";
        string RELATION = "relation";
        string RELATIONS = "relations";
        string POLICY = "policy";
        string POLICIES = "policies";
        string ATTRIBUTE = "attribute";
        string ATTRIBUTES = "attributes";
        string ATTRIBUTES_MANAGER = "attributes_manager";

        string SPACE = " +";
        string SPACE_OR_EMPTY = " *";
        string LEFT_BRACKET = "\\(" + SPACE_OR_EMPTY;
        string RIGHT_BRACKET = SPACE_OR_EMPTY + "\\)";
        string COMMA = SPACE_OR_EMPTY + "," + SPACE_OR_EMPTY;

        string NUMBER = "(0|[1-9][0-9]*)";  //数字，0或者正整数
        string VARIABLE = "'([a-zA-Z_][a-zA-Z0-9_@%]*)'";  //变量名，单引号括起来，字母或下划线开头，合法字符有：大小写字母、数字、下划线
        string ATTRIBUTE_VALUE =
            "'([a-zA-Z0-9_.\\?\\*\\-\\\\]*)'";  //数字或者变量名，单引号括起来，合法字符有：大小写字母、数字、下划线、点、杠、斜线、问号
        // string OBJECT = "'([a-zA-Z0-9_.*]*)'";  //对象名，单引号括起来，合法字符有：大小写字母、数字、下划线、点、星号
        string OBJECT = "'([a-zA-Z0-9_.*@%]*)'"; //主体名称：boss@%
        string RULE = "\"([\\s\\S]*)\"";        //常量字符串，双引号括起来，可以包含任意字符
        string NUMBER_OR_NULL = "(0|[1-9][0-9]*|null)";  //数字或者null
        string OPERATOR = "'([a-zA-Z>=<!]*)'";  //比较操作符，单引号括起来，合法字符有：大小写字母、大于号、等于号、小于号
        string ABE_ATT_LIST = "'([\\w\\s\\|=]+)'"; //ABE中，用户的属性列表，可以通过|分隔各属性，并通过=为特定属性赋值
        string USER_NAME = "['\"`]?(\\w+)['\"`]?"; //创建用户时的用户名
        string AT = "@"; //用户名和主机号之间的符号
        string USER_HOST = "['\"`]?([\\w\\.%]+)['\"`]?";   //创建用户时的主机号
        string PASSWD = "['\"](.*)['\"]";

        // create abac domain relation 'domain_low' to 'domain_high'
        string create_domain_relation = CREATE + SPACE + ABAC + SPACE + DOMAIN + SPACE + RELATION + SPACE + VARIABLE + SPACE + TO + SPACE + VARIABLE;

        // create abac domain 'domain_name'
        string create_domain = CREATE + SPACE + ABAC + SPACE + DOMAIN + SPACE + VARIABLE;

        // grant abac domain 'domain_name' to 'obejct'
        // 对象名可能包含特殊字符：点、星号
        string grant_domain = GRANT + SPACE + ABAC + SPACE + DOMAIN + SPACE + VARIABLE + SPACE + TO + SPACE + OBJECT;

        // drop abac domain relation 'domain_low' from 'domain_high'
        string drop_domain_relation = DROP + SPACE + ABAC + SPACE + DOMAIN + SPACE + RELATION + SPACE + VARIABLE + SPACE + FROM + SPACE + VARIABLE;

        // drop abac domain 'domain_name'
        string drop_domain = DROP + SPACE + ABAC + SPACE + DOMAIN + SPACE + VARIABLE;

        // show abac domains
        string show_domains = SHOW + SPACE + ABAC + SPACE + DOMAINS;

        // show abac domain relations
        string show_domain_relations = SHOW + SPACE + ABAC + SPACE + DOMAIN + SPACE + RELATIONS;

        // show abac domain on 'db_or_user_name'
        string show_user_or_db_domain = SHOW + SPACE + ABAC + SPACE + DOMAIN + SPACE + ON + SPACE + VARIABLE;

        // show abac domain on 'db_name' in 'table_name'
        string show_table_domain = SHOW + SPACE + ABAC + SPACE + DOMAIN + SPACE + ON + SPACE + VARIABLE + SPACE + IN + SPACE + VARIABLE;

        // create abac level relation 'level_low' to 'level_high'
        string create_level_relation = CREATE + SPACE + ABAC + SPACE + LEVEL + SPACE + RELATION + SPACE + VARIABLE + SPACE + TO + SPACE + VARIABLE;

        // create abac level 'level_name'
        string create_level = CREATE + SPACE + ABAC + SPACE + LEVEL + SPACE + VARIABLE;

        // grant abac level 'level_name' to 'obejct'
        string grant_level = GRANT + SPACE + ABAC + SPACE + LEVEL + SPACE + VARIABLE + SPACE + TO + SPACE + OBJECT;

        // drop abac level relation 'level_low' from 'level_high'
        string drop_level_relation = DROP + SPACE + ABAC + SPACE + LEVEL + SPACE + RELATION + SPACE + VARIABLE + SPACE + FROM + SPACE + VARIABLE;

        // drop abac level 'level_name'
        string drop_level = DROP + SPACE + ABAC + SPACE + LEVEL + SPACE + VARIABLE;

        // show abac levels
        string show_levels = SHOW + SPACE + ABAC + SPACE + LEVELS;

        // show abac level relations
        string show_level_relations = SHOW + SPACE + ABAC + SPACE + LEVEL + SPACE + RELATIONS;

        // show abac level on 'db_or_user_name'
        string show_user_or_db_level = SHOW + SPACE + ABAC + SPACE + LEVEL + SPACE + ON + SPACE + VARIABLE;

        // show abac level on 'db_name' in 'table_name'
        string show_table_level = SHOW + SPACE + ABAC + SPACE + LEVEL + SPACE + ON + SPACE + VARIABLE + SPACE + IN + SPACE + VARIABLE;

        // create abac attribute (id,'name','type')
        string create_attribute =
            CREATE + SPACE + ABAC + SPACE + ATTRIBUTE + SPACE + LEFT_BRACKET + NUMBER + COMMA + VARIABLE + COMMA + VARIABLE + RIGHT_BRACKET;

        // grant abac attribute ('attribute_name', 'attribute_value') to 'object'
        string grant_attribute = GRANT + SPACE + ABAC + SPACE + ATTRIBUTE + SPACE + LEFT_BRACKET + VARIABLE + COMMA + ATTRIBUTE_VALUE +
                                 RIGHT_BRACKET + SPACE + TO + SPACE + OBJECT;

        // revoke abac attribute ('attribute_name','attribute_value') from 'object'
        string revoke_attribute = REVOKE + SPACE + ABAC + SPACE + ATTRIBUTE + SPACE + LEFT_BRACKET + VARIABLE + COMMA + ATTRIBUTE_VALUE +
                                  RIGHT_BRACKET + SPACE + FROM + SPACE + OBJECT;

        // drop abac attribute 'attribute_name'
        string drop_attribute = DROP + SPACE + ABAC + SPACE + ATTRIBUTE + SPACE + VARIABLE;

        // show abac attributes
        string show_attributes = SHOW + SPACE + ABAC + SPACE + ATTRIBUTES;

        // show abac attributes_manager
        string show_attributes_manager = SHOW + SPACE + ABAC + SPACE + ATTRIBUTES_MANAGER;

        // create abac policy ('policy_name','subject','object','obj_type',
        // operation,'att_name','const_val','operator','tag',sub_att,obj_att,'enable')
        string create_policy = CREATE + SPACE + ABAC + SPACE + POLICY + SPACE + LEFT_BRACKET  // create abac policy
                               + VARIABLE + COMMA                                             // policy_name
                               + VARIABLE + COMMA                                             // subject
                               + OBJECT + COMMA                                               // object
                               + VARIABLE + COMMA                                             // obj_type
                               + NUMBER + COMMA                                               // operation
                               + VARIABLE + COMMA                                             // att_name
                               + RULE + COMMA                                                 // const_val
                               + OPERATOR + COMMA                                             // operator
                               + VARIABLE + COMMA                                             // tag
                               + NUMBER_OR_NULL + COMMA                                       // sub_att
                               + NUMBER_OR_NULL + COMMA                                       // obj_att
                               + VARIABLE + RIGHT_BRACKET;                                    // enable

        //
        string drop_policy = DROP + SPACE + ABAC + SPACE + POLICY + SPACE + VARIABLE;

        // show abac policies
        string show_policies = SHOW + SPACE + ABAC + SPACE + POLICIES;

        // alter abac policy 'policy_name' enable
        string enable_policy = ALTER + SPACE + ABAC + SPACE + POLICY + SPACE + VARIABLE + SPACE + ENABLE;

        // alter abac policy 'policy_name' disable
        string disable_policy = ALTER + SPACE + ABAC + SPACE + POLICY + SPACE + VARIABLE + SPACE + DISABLE;
        

        //abe相关命令：
        string create_user_and_att = CREATE + SPACE + USER + SPACE + USER_NAME + AT + USER_HOST + SPACE + IDENTIFIED + SPACE + BY + SPACE + PASSWD + SPACE + ABE + SPACE + ABE_ATT_LIST;
        string grant_abe_att = GRANT + SPACE + ABE + SPACE + ATTRIBUTE + SPACE + ABE_ATT_LIST + SPACE + TO + SPACE + USER_NAME + AT + USER_HOST;

        mp[CREATE_DOMAIN] = (SqlInfo){create_domain, 1};
        mp[CREATE_DOMAIN_RELATION] = (SqlInfo){create_domain_relation, 2};
        mp[GRANT_DOMAIN] = (SqlInfo){grant_domain, 2};
        mp[DROP_DOMAIN] = (SqlInfo){drop_domain, 1};
        mp[DROP_DOMAIN_RELATION] = (SqlInfo){drop_domain_relation, 2};
        mp[SHOW_DOMAINS] = (SqlInfo){show_domains, 0};
        mp[SHOW_DOMAIN_RELATIONS] = (SqlInfo){show_domain_relations, 0};
        mp[SHOW_USER_OR_DB_DOMAIN] = (SqlInfo){show_user_or_db_domain, 1};
        mp[SHOW_TABLE_DOMAIN] = (SqlInfo){show_table_domain, 2};

        mp[CREATE_LEVEL] = (SqlInfo){create_level, 1};
        mp[CREATE_LEVEL_RELATION] = (SqlInfo){create_level_relation, 2};
        mp[GRANT_LEVEL] = (SqlInfo){grant_level, 2};
        mp[DROP_LEVEL] = (SqlInfo){drop_level, 1};
        mp[DROP_LEVEL_RELATION] = (SqlInfo){drop_level_relation, 2};
        mp[SHOW_LEVELS] = (SqlInfo){show_levels, 0};
        mp[SHOW_LEVEL_RELATIONS] = (SqlInfo){show_level_relations, 0};
        mp[SHOW_USER_OR_DB_LEVEL] = (SqlInfo){show_user_or_db_level, 1};
        mp[SHOW_TABLE_LEVEL] = (SqlInfo){show_table_level, 2};

        mp[CREATE_ATTRIBUTE] = (SqlInfo){create_attribute, 3};
        mp[GRANT_ATTRIBUTE] = (SqlInfo){grant_attribute, 3};
        mp[REVOKE_ATTRIBUTE] = (SqlInfo){revoke_attribute, 3};
        mp[DROP_ATTRIBUTE] = (SqlInfo){drop_attribute, 1};
        mp[SHOW_ATTRIBUTES] = (SqlInfo){show_attributes, 0};
        mp[SHOW_ATTRIBUTES_MANAGER] = (SqlInfo){show_attributes_manager, 0};

        mp[CREATE_POLICY] = (SqlInfo){create_policy, 12};
        mp[DROP_POLICY] = (SqlInfo){drop_policy, 1};
        mp[SHOW_POLICIES] = (SqlInfo){show_policies, 0};
        mp[ENABLE_POLICY] = (SqlInfo){enable_policy, 1};
        mp[DISABLE_POLICY] = (SqlInfo){disable_policy, 1};
        mp[CREATE_USER_AND_ATT] = (SqlInfo){create_user_and_att, 4};
        mp[GRANT_ABE_ATT] = (SqlInfo){grant_abe_att, 3};

        for (int i = BEGIN + 1; i < END; i++) {
            mp[i].regex_expression = SPACE_OR_EMPTY + mp[i].regex_expression + SPACE_OR_EMPTY;
        }
    }

    //核心函数，使用正则表达式判断是否匹配
    bool isMatched(CommandType command_type)
    {
        std::smatch result;
        string regex_expression = mp[command_type].regex_expression;
        // std::regex pattern = std::regex(regex_expression, regex::icase);
        std::regex pattern = std::regex(regex_expression);
        bool isMatch = std::regex_match(target, result, pattern);
        if (isMatch) {
            this->command_type = command_type;
            int arguments_number = mp[command_type].arguments_number;
            for (int i = 1; i <= arguments_number; i++) {
                arguments.push_back(result[i]);
            }
        }
        return isMatch;
    }

   public:
    SqlParser(string target)
    {
        this->target = target;
        initMap();
    }
    CommandType command_type;
    vector<string> arguments;

    //检测create policy指令的constValue是否合法
    bool checkPolicyConstValue()
    {
        if (command_type != CREATE_POLICY) {
            return true;
        }
        string attr_name = arguments[5];
        string attr_value = arguments[6];
        string regex_expression;
        if (attr_name == "time") {
            regex_expression = "([0-1]\\d|2[0-3]):([0-5]\\d):([0-5]\\d)";
        } else if (attr_name == "date") {
            regex_expression = "\\d{4}-(((0[13578]|(10|12))-(0[1-9]|[1-2]\\d|3[0-1]))|(02-(0[1-9]|[1-2]\\d))|((0[469]|11)-(0[1-9]|[1-2]\\d|30)))";
        } else if (attr_name == "weekday") {
            regex_expression = "[1-7]";
        } else if (attr_name == "ip") {
            regex_expression = "((25[0-5]|2[0-4]\\d|((1\\d{2})|([1-9]?\\d)))\\.){3}(25[0-5]|2[0-4]\\d|((1\\d{2})|([1-9]?\\d)))";
        } else {
            return true;
        }
        regex_expression = "'" + regex_expression + "'";
        std::regex pattern = std::regex(regex_expression);
        return std::regex_match(attr_value, pattern);
    }

    //解析函数入口
    bool sqlParsing()
    {
        //把字符串转换为小写
        transform(target.begin(), target.end(), target.begin(), ::tolower);
        //预检查，判断是否包含特殊关键字abac
        if (target.find("abac") == string::npos && target.find("abe") == string::npos) {
            return false;
        }
        for (int i = BEGIN + 1; i < END; i++) {
            if (isMatched((CommandType)i) && checkPolicyConstValue()) {
                return true;
            }
        }
        return false;
    }
};





//语法解析函数，匹配指令，执行相应的函数
//解析成功返回true，失败返回false
bool sqlParsing(THD* thd, COM_DATA com_data)
{
    string command = com_data.com_query.query;
    SqlParser* parser = new SqlParser(command);

    //解析失败
    if (!(parser->sqlParsing())) {
        delete parser;
        return false;
    }

    //解析成功，填充参数
    vector<LEX_STRING> paramaters;
    for (unsigned int i = 0; i < parser->arguments.size(); i++) {
        LEX_STRING paramater;
        paramater.str = const_cast<char*>(parser->arguments[i].c_str());
        paramater.length = parser->arguments[i].size();
        paramaters.push_back(paramater);
    }

    switch (parser->command_type) {
        case CREATE_DOMAIN:  
            mysql_add_domain_sec(thd,paramaters);
            delete parser;
            return true;
        case CREATE_DOMAIN_RELATION:   //create domain 'domain_name' to 'domain_name'
            mysql_add_domain_relation(thd,paramaters);
            delete parser;
            return true;
        case GRANT_DOMAIN:
            grant_domain_to_obj(thd,paramaters);
            delete parser;
            return true;
        case DROP_DOMAIN:
            mysql_delete_domain_sec(thd,paramaters);
            delete parser;
            return true;
        case DROP_DOMAIN_RELATION:   
            mysql_delete_domain_relation(thd,paramaters);
            delete parser;
            return true;
        case SHOW_DOMAINS:    //show domains
            show_all_domain(thd);
            delete parser;
            return true;
        case SHOW_DOMAIN_RELATIONS:  //show domain relation
            show_all_domain_relation(thd);
            delete parser;
            return true;
        case SHOW_USER_OR_DB_DOMAIN://show domain on 'obj_name' 只有一个参数 查询 用户 或者数据库所具有的 范畴
        case SHOW_TABLE_DOMAIN:    //show domain on 'db_name' in 'table_name' 两个参数 数据库中的某个表 具有的范畴
            mysql_show_domain(thd,paramaters);
            delete parser;
            return true;



        case CREATE_LEVEL:  //create level 'lowlevel_name' to 'hign_level_name'
            mysql_add_level_sec(thd,paramaters);
            delete parser;
            return true;
        case CREATE_LEVEL_RELATION:  //create level 'lowlevel_name' to 'hign_level_name'
            mysql_add_level_realtion(thd,paramaters);
            delete parser;
            return true;
        case GRANT_LEVEL:
            grant_level_to_obj(thd,paramaters);
            delete parser;
            return true;
        case DROP_LEVEL:  //create level 'lowlevel_name' to 'hign_level_name'
            mysql_delete_level_sec(thd,paramaters);
            delete parser;
            return true;
        case DROP_LEVEL_RELATION: //delete level 'level_name'
            mysql_delete_level_relation(thd,paramaters);
            delete parser;
            return true;
        case SHOW_LEVELS:  // show levels
            show_all_level(thd);
            delete parser;
            return true;
        case SHOW_LEVEL_RELATIONS: //show level relation
            show_all_level_relation(thd);
            delete parser;
            return true;
        case SHOW_USER_OR_DB_LEVEL:
        case SHOW_TABLE_LEVEL:
            mysql_show_level(thd,paramaters);
            delete parser;
            return true;
        



        /**add by yuang in 20221005  start */
        case CREATE_ATTRIBUTE:
            mysql_add_attribute(thd,paramaters); //create attribute ('id','name','type')
            delete parser;
            return true;
        case GRANT_ATTRIBUTE:
            mysql_add_attribute_manager(thd,paramaters); //grant attribute 'attribute_name'('attribute_value') to 'object'
            delete parser;
            return true;
        case REVOKE_ATTRIBUTE:
            mysql_delete_attribute_manager(thd,paramaters); //revoke attribute 'attribute_name' from 'object'
            delete parser;
            return true;
        case DROP_ATTRIBUTE:
            mysql_delete_attribute(thd,paramaters); 
            delete parser;
            return true;
        case SHOW_ATTRIBUTES:
            show_all_attributes(thd); //show attributes
            delete parser;
            return true;
        case SHOW_ATTRIBUTES_MANAGER:
            show_all_attributes_manager(thd); //show attributes_manager
            delete parser;
            return true;


        case CREATE_POLICY:
            mysql_add_policy(thd,paramaters); 
            delete parser;
            return true;
        
        case DROP_POLICY:
            mysql_delete_policy(thd,paramaters); 
            delete parser;
            return true;
        case SHOW_POLICIES:
            show_all_policy(thd); //show policys
            delete parser;
            return true;
        case ENABLE_POLICY:
            alter_policy_enable(thd,paramaters); //show policys
            delete parser;
            return true;
        case DISABLE_POLICY:
            alter_policy_disable(thd,paramaters); //show policys
            delete parser;
            return true;
        case CREATE_USER_AND_ATT:
            create_user_and_att(thd, paramaters);
            delete parser;
            return true;
        case GRANT_ABE_ATT:
            grant_abe_att(thd, paramaters);
            delete parser;
            return true;
    }
}



/*****************语法解析部分 end*************************/


void reset_statement(THD *thd)
{
    /* PSI end */
    thd->send_statement_status();
    MYSQL_END_STATEMENT(thd->m_statement_psi, thd->get_stmt_da());
    thd->m_statement_psi = nullptr;
    thd->m_digest = nullptr;
}

//在abac_domain_sec中没有 就返回 true
bool not_has_son_domain(THD* thd,int len ,char *str)
{
    TABLE *table;
    unique_ptr_destroy_only<RowIterator> iterator;
    bool result;
    MEM_ROOT tmp_root{PSI_NOT_INSTRUMENTED, 4096};
    TABLE_LIST tables("mysql", "abac_domain_sec", TL_READ);  //abac_level_sec
    tables.open_strategy = TABLE_LIST::OPEN_NORMAL;
    result= open_trans_system_tables_for_read(thd, &tables);
    if (result)  return false;
    table = tables.table;
    iterator = init_table_iterator(thd, table, false, false);
    if (iterator == nullptr)
    {
        close_trans_system_tables(thd);
        return false;
    }
    table->use_all_columns();
    int read_rec_errcode;
    bool res = true;
    while (!(read_rec_errcode = iterator->Read()))
    {
        String recd;
        get_field(&tmp_root, table->field[0], &recd);
        if( recd.length() == len && strncmp( recd.ptr(),str,len) == 0) { res = false;break;  }
    }
    iterator.reset();
    table->invalidate_dict();
    close_trans_system_tables(thd);
    return res;
}


bool not_has_son_level(THD* thd,int len ,char *str)
{
    TABLE *table;
    unique_ptr_destroy_only<RowIterator> iterator;
    bool result;
    MEM_ROOT tmp_root{PSI_NOT_INSTRUMENTED, 4096};
    TABLE_LIST tables("mysql", "abac_level_sec", TL_READ);  //abac_level_sec
    tables.open_strategy = TABLE_LIST::OPEN_NORMAL;
    result= open_trans_system_tables_for_read(thd, &tables);
    if (result)  return false;
    table = tables.table;
    iterator = init_table_iterator(thd, table, false, false);
    if (iterator == nullptr)
    {
        close_trans_system_tables(thd);
        return false;
    }
    table->use_all_columns();
    int read_rec_errcode;
    bool res = true;
    while (!(read_rec_errcode = iterator->Read()))
    {
        String recd;
        get_field(&tmp_root, table->field[0], &recd);
        if( recd.length() == len && strncmp( recd.ptr(),str,len) == 0) { res = false;break;  }
    }
    iterator.reset();
    table->invalidate_dict();
    close_trans_system_tables(thd);
    return res;
}


bool mysql_add_domain_relation(THD *thd,vector<LEX_STRING>& paramaters)
{
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }
    	
    LEX_CSTRING DB = {"mysql",5};
    LEX_CSTRING TABLE = {"abac_domain_sec_poset",21};
    if(check_sign(thd, DB, TABLE))
    {
    	send_access_deny(thd);
        reset_statement(thd);
    	return true;
    }

    LEX_STRING son = paramaters[0];
    LEX_STRING parent = paramaters[1];
    bool nothas = not_has_son_domain(thd,son.length,son.str);

    
    //new added by yuang in 2022.9.26 公共内存上锁
    Acl_cache_lock_guard acl_cache_lock(thd, Acl_cache_lock_mode::WRITE_MODE);
    if (!acl_cache_lock.lock()) return true;

    bool res = true;
    if(nothas == false) res = add_domain(parent.str, parent.length, son.str, son.length);
    else res = false;

    //new added by yuang in 2022.9.26 公共内存解锁
    acl_cache_lock.unlock();

    if (res)
    {
        string command = "insert into mysql.abac_domain_sec_poset(domain_h,domain_l) values('";
        command += parent.str;
        command += "','";
        command += son.str;
        command += "')";

        int len = command.length()+5;

        COM_DATA cmd;
        memset(&cmd, 0, sizeof(cmd));
        //char buf[300] ={0};
        char *buf = new char[len];
        memset(buf,0,len);

        strcpy(buf, command.c_str());
        cmd.com_query.query = reinterpret_cast<const char *>(buf);
        cmd.com_query.length = static_cast<unsigned int>(command.length());
        res = dispatch_command(thd, &cmd, COM_QUERY);

        delete[] buf;
    }
    else
    {
        //MEM_ROOT *mem_root= thd->mem_root;
        mem_root_deque<Item *> field_list(thd->mem_root);
        field_list.push_back(new Item_empty_string("result", 10));
        Protocol *protocol = thd->get_protocol();
        if (thd->send_result_metadata(field_list, Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
            return true; //DBUG_RETURN(true);
        protocol->start_row();
        protocol->store_string("fail", 4, system_charset_info);
        if (protocol->end_row())
            return true; //DBUG_RETURN(true);
        my_eof(thd);
        reset_statement(thd);
    }
    return res; //DBUG_RETURN(false);
}

bool mysql_add_level_realtion(THD *thd,vector<LEX_STRING>& paramaters)
{
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }
    LEX_CSTRING DB = {(char *)"mysql", 5};
    LEX_CSTRING TABLE = {(char *)"abac_level_sec_poset", 20};
    if (check_sign(thd, DB, TABLE))
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }

    LEX_STRING son = paramaters[0];
    LEX_STRING parent = paramaters[1];
    bool nothas = not_has_son_level(thd,son.length,son.str);  //首先在level_sec中需要有 son_level

    //new added by yuang in 2022.9.26 公共内存上锁
    Acl_cache_lock_guard acl_cache_lock(thd, Acl_cache_lock_mode::WRITE_MODE);
    if (!acl_cache_lock.lock()) return true;

    bool res = true;
    if(nothas == false) res = add_level(parent.str, parent.length, son.str, son.length);
    else res = false;

    //new added by yuang in 2022.9.26 公共内存解锁
    acl_cache_lock.unlock();

    if (res)
    {
        string command = "insert into mysql.abac_level_sec_poset(level_h,level_l) values('";
        command += parent.str;
        command += "','";
        command += son.str;
        command += "')";

        COM_DATA cmd;
        memset(&cmd, 0, sizeof(cmd));
        //char buf[200]= {0};
        int len = command.length()+5;
        char *buf = new char[len];
        memset(buf,0,len);
        
        strcpy(buf, command.c_str());
        cmd.com_query.query = reinterpret_cast<const char *>(buf);
        cmd.com_query.length = static_cast<unsigned int>(command.length());

        res = dispatch_command(thd, &cmd, COM_QUERY);
        delete[] buf;
    }
    else
    {
        //MEM_ROOT *mem_root= thd->mem_root;
        mem_root_deque<Item *> field_list(thd->mem_root);
        Protocol *protocol = thd->get_protocol();
        field_list.push_back(new Item_empty_string("result", 10));
        if (thd->send_result_metadata(field_list, Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
            return true; //DBUG_RETURN(true);
        protocol->start_row();
        protocol->store_string("fail", 4, system_charset_info);
        if (protocol->end_row())
            return true; //DBUG_RETURN(true);
        my_eof(thd);
        reset_statement(thd);
    }
    return res; //DBUG_RETURN(false);
}

bool mysql_delete_domain_relation(THD *thd,vector<LEX_STRING>& paramaters)
{
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }
    LEX_CSTRING DB = {(char *)"mysql", 5};
    LEX_CSTRING TABLE = {(char *)"abac_domain_sec_poset", 21};
    if (check_sign(thd, DB, TABLE))
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }

    LEX_STRING domain_l = paramaters[0];
    LEX_STRING domain_h = paramaters[1];

    //new added by yuang in 2022.9.26 公共内存上锁
    Acl_cache_lock_guard acl_cache_lock(thd, Acl_cache_lock_mode::WRITE_MODE);
    if (!acl_cache_lock.lock()) return true;
    bool res = delete_domain(domain_l.str, domain_l.length);
    //new added by yuang in 2022.9.26 公共内存解锁
    acl_cache_lock.unlock();

    if (res)
    {
        string command = "delete from mysql.abac_domain_sec_poset where domain_h='";
        command += domain_h.str;
        command += "' and domain_l = '";
        command += domain_l.str;
        command += "'";

        COM_DATA cmd;
        memset(&cmd, 0, sizeof(cmd));
        //char buf[200] ={0};
        
        int len = command.length()+5;
        char *buf = new char[len];
        memset(buf,0,len);
        
        strcpy(buf, command.c_str());
        cmd.com_query.query = reinterpret_cast<const char *>(buf);
        cmd.com_query.length = static_cast<unsigned int>(command.length());

        res = dispatch_command(thd, &cmd, COM_QUERY);
        delete[] buf;
    }
    else
    {
        //MEM_ROOT *mem_root= thd->mem_root;
        mem_root_deque<Item *> field_list(thd->mem_root);
        Protocol *protocol = thd->get_protocol();
        field_list.push_back(new Item_empty_string("result", 10));
        if (thd->send_result_metadata(field_list, Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
            return true; //DBUG_RETURN(true);
        protocol->start_row();
        protocol->store_string("fail", 4, system_charset_info);
        if (protocol->end_row())
            return true; //DBUG_RETURN(true);
        my_eof(thd);
        reset_statement(thd);
    }
    return res; //DBUG_RETURN(false);
}

bool mysql_delete_level_relation(THD *thd,vector<LEX_STRING>& paramaters)
{
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }
    LEX_CSTRING DB = {(char *)"mysql", 5};
    LEX_CSTRING TABLE = {(char *)"abac_level_sec_poset", 20};
    if (check_sign(thd, DB, TABLE))
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }

    LEX_STRING level_l = paramaters[0];
    LEX_STRING level_h = paramaters[1];

    //new added by yuang in 2022.9.26 公共内存上锁
    Acl_cache_lock_guard acl_cache_lock(thd, Acl_cache_lock_mode::WRITE_MODE);
    if (!acl_cache_lock.lock()) return true;

    bool res = delete_level(level_h.str,level_h.length,level_l.str, level_l.length); //bool res = true;

    //new added by yuang in 2022.9.26 公共内存解锁
    acl_cache_lock.unlock();

    if (res)
    {
        string command = "delete from mysql.abac_level_sec_poset where level_l='";
        command += level_l.str;
        command += "' and level_h = '";
        command += level_h.str;
        command += "'";

        COM_DATA cmd;
        memset(&cmd, 0, sizeof(cmd));
        //char buf[200] = {0};
        
        int len = command.length()+5;
        char *buf = new char[len];
        memset(buf,0,len);
        
        strcpy(buf, command.c_str());
        cmd.com_query.query = reinterpret_cast<const char *>(buf);
        cmd.com_query.length = static_cast<unsigned int>(command.length());
        res = dispatch_command(thd, &cmd, COM_QUERY);
        
        delete[] buf;        
    }
    else
    {
        //MEM_ROOT *mem_root= thd->mem_root;
        mem_root_deque<Item *> field_list(thd->mem_root);
        Protocol *protocol = thd->get_protocol();
        field_list.push_back(new Item_empty_string("result", 10));
        if (thd->send_result_metadata(field_list, Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
            return true; //DBUG_RETURN(true);
        protocol->start_row();
        protocol->store_string("fail", 4, system_charset_info);
        if (protocol->end_row())
            return true; //DBUG_RETURN(true);
        my_eof(thd);
        reset_statement(thd);
    }
    return res; //DBUG_RETURN(false);
}

void send_access_deny(THD *thd)
{
    //MEM_ROOT *mem_root= thd->mem_root;
    mem_root_deque<Item *> field_list(thd->mem_root);
    Protocol *protocol = thd->get_protocol();
    field_list.push_back(new Item_empty_string("result", 10));
    if (thd->send_result_metadata(field_list, Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
        return;
    protocol->start_row();
    protocol->store_string("access denied", 13, system_charset_info);

    if (protocol->end_row())
        return;
    my_eof(thd);
}


void send_fail_res(THD *thd)
{
    //MEM_ROOT *mem_root= thd->mem_root;
    mem_root_deque<Item *> field_list(thd->mem_root);
    Protocol *protocol = thd->get_protocol();
    field_list.push_back(new Item_empty_string("result", 10));
    if (thd->send_result_metadata(field_list, Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
        return;
    protocol->start_row();
    protocol->store_string("init fail", 9, system_charset_info);

    if (protocol->end_row())
        return;
    my_eof(thd);
}


void send_cant_delete_root(THD *thd)
{
    //MEM_ROOT *mem_root= thd->mem_root;
    mem_root_deque<Item *> field_list(thd->mem_root);
    Protocol *protocol = thd->get_protocol();
    field_list.push_back(new Item_empty_string("result", 10));
    if (thd->send_result_metadata(field_list, Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
        return;
    protocol->start_row();
    protocol->store_string("can't delete root", 17, system_charset_info);

    if (protocol->end_row())
        return;
    my_eof(thd);
}

void send_cant_delete_level(THD *thd)
{
    //MEM_ROOT *mem_root= thd->mem_root;
    mem_root_deque<Item *> field_list(thd->mem_root);
    Protocol *protocol = thd->get_protocol();
    field_list.push_back(new Item_empty_string("result", 10));
    if (thd->send_result_metadata(field_list, Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
        return;
    protocol->start_row();
    protocol->store_string("can't delete highest", 20, system_charset_info);

    if (protocol->end_row())
        return;
    my_eof(thd);
}

bool mysql_show_level(THD *thd,vector<LEX_STRING>& paramaters)
{
    int cnt  = paramaters.size();
    bool res;
    LEX_STRING db;
    LEX_STRING table;
    if(cnt == 1)
    {
        db = paramaters[0];
    }
    else  if(cnt == 2)
    {
        db = paramaters[0];
        table = paramaters[1];
    }
    
    if (cnt == 1)
    {
        string command = "select * from mysql.abac_attribute_manager where (object='";
        command += db.str;
        command += ".*' or object = '";
        command += db.str; /*  用户  数据库 都能查  */
        command += "') and att_name ='level'";

        COM_DATA cmd;
        memset(&cmd, 0, sizeof(cmd));
        //char buf[300]= {0};
        int len = command.length()+5;
        char *buf = new char[len];
        memset(buf,0,len);

        strcpy(buf, command.c_str());
        cmd.com_query.query = reinterpret_cast<const char *>(buf);
        cmd.com_query.length = static_cast<unsigned int>(command.length());

        res =  dispatch_command(thd, &cmd, COM_QUERY);
        delete[] buf;
        return res;
    }
    else if(cnt == 2)
    {
        string command = "select * from mysql.abac_attribute_manager where object='";
        command += db.str;
        command += ".";
        command += table.str;
        command += "' and att_name ='level'";

        COM_DATA cmd;
        memset(&cmd, 0, sizeof(cmd));
        //char buf[300]= {0};
        
        int len = command.length()+5;
        char *buf = new char[len];
        memset(buf,0,len);        
        
        
        strcpy(buf, command.c_str());
        cmd.com_query.query = reinterpret_cast<const char *>(buf);
        cmd.com_query.length = static_cast<unsigned int>(command.length());

        res =  dispatch_command(thd, &cmd, COM_QUERY);
        delete[] buf;
        return res;
    }
}

bool mysql_show_domain(THD *thd,vector<LEX_STRING>& paramaters)
{
    int cnt  = paramaters.size();
    bool res;
    LEX_STRING db;
    LEX_STRING table;
    if(cnt == 1)
    {
        db = paramaters[0];
    }
    else  if(cnt == 2)
    {
        db = paramaters[0];
        table = paramaters[1];
    }
    
    if (cnt == 1)
    {
        string command = "select * from mysql.abac_attribute_manager where (object='";
        command += db.str;
        command += ".*' or object = '";
        command += db.str; /*  用户  数据库 都能查  */
        command += "') and att_name ='domain'";

        COM_DATA cmd;
        memset(&cmd, 0, sizeof(cmd));
        //char buf[300] = {0};
        
        int len = command.length()+5;
        char *buf = new char[len];
        memset(buf,0,len);
        
        strcpy(buf, command.c_str());
        cmd.com_query.query = reinterpret_cast<const char *>(buf);
        cmd.com_query.length = static_cast<unsigned int>(command.length());
       
        res =  dispatch_command(thd, &cmd, COM_QUERY);
        delete[] buf;
        return res;
    }
    else if(cnt == 2)
    {
        string command = "select * from mysql.abac_attribute_manager where object='";
        command += db.str;
        command += ".";
        command += table.str;
        command += "' and att_name ='domain'";

        COM_DATA cmd;
        memset(&cmd, 0, sizeof(cmd));
        //char buf[300]= {0};
        
        int len = command.length()+5;
        char *buf = new char[len];
        memset(buf,0,len);
        
        strcpy(buf, command.c_str());
        cmd.com_query.query = reinterpret_cast<const char *>(buf);
        cmd.com_query.length = static_cast<unsigned int>(command.length());

        res =  dispatch_command(thd, &cmd, COM_QUERY);
        delete[] buf;
        return res;
    }
}

bool init_domain(THD *thd, vector<BRIM> &list)
{
    list.clear();
    BRIM tmp;
    //TABLE_LIST tables;
    TABLE *table;

    //READ_RECORD read_record_info;
    unique_ptr_destroy_only<RowIterator> iterator;

    bool result;
    DBUG_ENTER("init_domain");
    //MEM_ROOT tmp_root;
    MEM_ROOT tmp_root{PSI_NOT_INSTRUMENTED, 4096};

    TABLE_LIST tables("mysql", "abac_domain_sec_poset", TL_READ);


    //tables.init_one_table(&db_args,&table_args,NULL, TL_READ);
    tables.open_strategy = TABLE_LIST::OPEN_NORMAL;

    //result= open_and_lock_tables(thd, &tables, FALSE, MYSQL_LOCK_IGNORE_TIMEOUT);
    result= open_trans_system_tables_for_read(thd, &tables);


    if (result)
    {
        DBUG_PRINT("error", ("Can't open abac_domain_sec_poset table"));
        goto end;
    }
    table = tables.table;
    //result = init_read_record(&read_record_info, thd, table, NULL, NULL,1, 0, FALSE);

    iterator = init_table_iterator(thd, table, false, false);
    if (iterator == nullptr)
    {
        close_trans_system_tables(thd);
        DBUG_PRINT("error", ("Could not initialize init_read_record: domain_sec_poset not loaded"));
        //    DBUG_PRINT("Could not initialize init_read_record; domain_sec_poset not ", "loaded");
        goto end;
    }

    table->use_all_columns();
    //这里根据10.3.23其他程序的调用方式改成了没有参数的
    //while (!(error= read_record_info.read_record(&read_record_info)))

    int read_rec_errcode;
    while (!(read_rec_errcode = iterator->Read()))
    {
        DBUG_PRINT("info", ("init domain_sec_poset record"));
        String str_h, str_l;
        get_field(&tmp_root, table->field[0], &str_h);
        get_field(&tmp_root, table->field[1], &str_l);
        /*tzj
        if (str_h.length() == 0)
            tmp.uper = "";
        else
        */
        tmp.uper = str_h.ptr();
        tmp.lower = str_l.ptr();
        list.push_back(tmp);
        //free_root(&tmp_root, MYF(MY_MARK_BLOCKS_FREE));
    }
    //end_read_record(&read_record_info);
    iterator.reset();

    //table->m_needs_reopen= TRUE;                  // Force close to free memory
    table->invalidate_dict();

    close_trans_system_tables(thd);

    DBUG_RETURN(true);
end:
    DBUG_RETURN(false);
}

bool init_level(THD *thd, vector<BRIM> &list)
{
    list.clear();
    BRIM tmp;
    TABLE *table;

    unique_ptr_destroy_only<RowIterator> iterator;
    bool result;
    DBUG_ENTER("init_level");
    MEM_ROOT tmp_root{PSI_NOT_INSTRUMENTED, 4096};
    TABLE_LIST tables("mysql", "abac_level_sec_poset", TL_READ);

    tables.open_strategy = TABLE_LIST::OPEN_NORMAL;

    //result= open_and_lock_tables(thd, &tables, FALSE, MYSQL_LOCK_IGNORE_TIMEOUT);
    result= open_trans_system_tables_for_read(thd, &tables);
    if (result)
    {
        DBUG_PRINT("error", ("Can't open level_sec_poset table"));
        goto end;
    }
    table = tables.table;
    // result = init_read_record(&read_record_info, thd, table, NULL, NULL, 1, 0, FALSE);
    iterator = init_table_iterator(thd, table, false, false);

    if (iterator == nullptr)
    {
        close_trans_system_tables(thd);
        DBUG_PRINT("error", ("Could not initialize init_read_record: level_sec_poset not loaded"));
        //    DBUG_PRINT("Could not initialize init_read_record; level_sec_poset not ", "loaded");
        goto end;
    }

    table->use_all_columns();
    //while (!(error= read_record_info.read_record(&read_record_info)))
    //这里同理

    int read_rec_errcode;
    while (!(read_rec_errcode = iterator->Read()))
    {
        DBUG_PRINT("info", ("init abac_level_sec_poset record"));
        String str_h, str_l;
        get_field(&tmp_root, table->field[0], &str_h);
        get_field(&tmp_root, table->field[1], &str_l);
        /*
        if (str_h.length() == 0)
            tmp.uper = "";
        else
        */
        tmp.uper = str_h.ptr();
        tmp.lower = str_l.ptr();
        list.push_back(tmp);
        //free_root(&tmp_root, MYF(MY_MARK_BLOCKS_FREE));
    }
    //end_read_record(&read_record_info);
    iterator.reset();

    //table->m_needs_reopen= TRUE;                  // Force close to free memory
    table->invalidate_dict();

    close_trans_system_tables(thd);
    DBUG_RETURN(true);
end:
    DBUG_RETURN(false);
}

//no update
void init_level(vector<BRIM> &list)
{
    uint i;
    string uper, lower;
    vector<int> tags(list.size()+1,0);

    uper = "highest";
    add_level(NULL, 0, uper.c_str(), uper.length());
    
    while (1)
    {
        for (i = 0; i < list.size(); ++i)
        {
            if(tags[i] == 1) continue;
            if(list[i].uper == uper)
                break;
        }
        if ( i  == list.size())
            break;

        lower = list[i].lower;
        tags[i] = 1;
        add_level(uper.c_str(), uper.length(), lower.c_str(), lower.length());
        uper = lower;
    }
}

//no update
void init_domain(vector<BRIM> &list)
{
    uint i;
    queue<string> que;
    vector<int> tags(list.size()+1,0);
    string uper, lower;

    uper = "root";
    que.push(uper);
    add_domain(NULL, 0, uper.c_str(), uper.length());
    while (!que.empty())
    {
        uper = que.front();
        que.pop();
        for (i = 0; i < list.size();++i)
        {
            if(tags[i] == 1) continue;
            if(list[i].uper == uper)
            {
                lower = list[i].lower;
                add_domain(uper.c_str(), uper.length(), lower.c_str(), lower.length());
                que.push(list[i].lower);
                tags[i] = 1;
            }
        }
    }
}

//no update
// 在mysql自己的逻辑里面 
// 返回true代表有问题
// 返回false 代表没问题
bool init_sign(THD *thd)
{
    // LEX_CSTRING DB = {(char *)"mysql", 5};
    string priv_user = thd->security_context()->priv_user().str;
    string priv_host = thd->security_context()->priv_host().str;
    string sub = priv_user + "@" + priv_host;
    if ( sub != "abac_supervisor@%" && sub != "root@localhost")
    {
        send_access_deny(thd);  
        return false;
    }

    if (init){        
        my_ok(thd);
        return false;
    }
    init_domain_and_level();

    vector<BRIM> level_list, domain_list;
    if (!init_domain(thd, domain_list) || !init_level(thd, level_list))
    {
        //初始化失败
        send_fail_res(thd);
        return true;
    }
        
    //new added by yuang in 2022.9.26 公共内存上锁
    Acl_cache_lock_guard acl_cache_lock(thd, Acl_cache_lock_mode::WRITE_MODE);
    if (!acl_cache_lock.lock()) return true;

    init_domain(domain_list);
    init_level(level_list);

    //new added by yuang in 2022.9.26 公共内存解锁
    acl_cache_lock.unlock();

    // 如果失败  返回值是false 代表失败
    if(init_att_map(thd) == false )    //1
    {
        send_fail_res(thd);
        return true;
    }

    // 如果失败
    if(init_policy_map(thd) == false) //2
    {
        send_fail_res(thd);
        return true;
    }
    //added in 2022.1.24 by yuang
    my_ok(thd);
    init = true;
    return false;
}

bool show_all_domain(THD *thd)
{
    LEX_CSTRING DB = {(char *)"mysql", 5};
    LEX_CSTRING TABLE = {(char *)"abac_domain_sec", 15};
    if (check_sign(thd, DB, TABLE))
    {
        send_access_deny(thd);
        reset_statement(thd);
        return false;
    }

    string command = "select * from mysql.abac_domain_sec";

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    char buf[150] = {0};
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    return dispatch_command(thd, &cmd, COM_QUERY);
}

bool show_all_level(THD *thd)
{
    LEX_CSTRING DB = {(char *)"mysql", 5};
    LEX_CSTRING TABLE = {(char *)"abac_level_sec", 14};
    if (check_sign(thd, DB, TABLE))
    {
        send_access_deny(thd);
        reset_statement(thd);
        return false;
    }

    string command = "select * from mysql.abac_level_sec";

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    char buf[150] = {0};
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    return dispatch_command(thd, &cmd, COM_QUERY);
}

bool show_all_domain_relation(THD *thd)
{
    LEX_CSTRING DB = {(char *)"mysql", 5};
    LEX_CSTRING TABLE = {(char *)"abac_domain_sec_poset", 21};
    if (check_sign(thd, DB, TABLE))
    {
        send_access_deny(thd);
        reset_statement(thd);
        return false;
    }

    string command = "select * from mysql.abac_domain_sec_poset";

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    char buf[150] = {0};
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    return dispatch_command(thd, &cmd, COM_QUERY);
}

bool show_all_level_relation(THD *thd)
{
    LEX_CSTRING DB = {(char *)"mysql", 5};
    LEX_CSTRING TABLE = {(char *)"abac_level_sec_poset", 20};
    if (check_sign(thd, DB, TABLE))
    {
        send_access_deny(thd);
        reset_statement(thd);
        return false;
    }

    string command = "select * from mysql.abac_level_sec_poset";

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    char buf[150] = {0};
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    return dispatch_command(thd, &cmd, COM_QUERY);
}



/**add by yuang in 20221005  start */
bool mysql_add_policy(THD *thd,vector<LEX_STRING>& paramaters)
{
    bool res;
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }

    LEX_STRING policy_name = paramaters[0];
    LEX_STRING subject = paramaters[1];
    LEX_STRING object = paramaters[2];
    LEX_STRING obj_typ = paramaters[3];
    LEX_STRING operation = paramaters[4];
    LEX_STRING att_name = paramaters[5];
    LEX_STRING const_val = paramaters[6];
    LEX_STRING operator_str = paramaters[7];
    LEX_STRING tag = paramaters[8];
    LEX_STRING sub_att  = paramaters[9];
    LEX_STRING  obj_att = paramaters[10];
    LEX_STRING is_enable = paramaters[11];

    if(is_enable.length == 4 && strncmp(is_enable.str,"true",4) == 0) // 如果插入的策略 enable字段是有效     则进行检测
    {
        if(subject.length != 3  || (subject.length == 3 && strncmp(subject.str,"any",3)!=0 )  ) //  sub没有 any 
        {
            if(object.length != 3  || (object.length == 3 && strncmp(object.str,"any",3)!=0 )  ) //  obj 没有any 
            {
                if(tag.length != 14  || (tag.length == 14 && strncmp(tag.str,"envvalconstval",14)!=0)) // tag不能有环境
                {
                    // 组合策略
                    POLICY policy;
                    policy.subject.clear();
                    policy.object.clear();
                    policy.left.clear();
                    policy.oper.clear();
                    policy.right.clear();


                    if(strncmp((char *)operator_str.str, "contain", operator_str.length) == 0)
                    {
                        if(strncmp((char *)tag.str, "attvalattval", tag.length) == 0)
                        {
                            policy.left.append("O.");
                            policy.left.append(att_name.str, att_name.length);
                            
                            policy.oper.append("in");

                            policy.right.append("S.");
                            policy.right.append(att_name.str, att_name.length);
                        }
                        else if(strncmp((char *)tag.str, "attvalconstval", tag.length) == 0)
                        {
                            policy.left.append(const_val.str, const_val.length);
                            policy.oper.append("in");
                            policy.right.append("S.");
                            policy.right.append(att_name.str, att_name.length);
                        }
                    }
                    else if(strncmp((char *)operator_str.str, "uncontain", operator_str.length) == 0)
                    {
                        if(strncmp((char *)tag.str, "attvalattval", tag.length) == 0)
                        {
                            policy.left.append("O.");
                            policy.left.append(att_name.str, att_name.length);
                            policy.oper.append("notin");
                            policy.right.append("S.");
                            policy.right.append(att_name.str, att_name.length);
                        }
                        else if(strncmp((char *)tag.str, "attvalconstval", tag.length) == 0)
                        {
                            policy.left.append(const_val.str, const_val.length);
                            policy.oper.append("notin");
                            policy.right.append("S.");
                            policy.right.append(att_name.str, att_name.length);
                        }
                    }
                    else
                    {
                        if(strncmp((char *)tag.str, "attvalattval", tag.length) == 0)
                        {
                            policy.left.append("S.");
                            policy.left.append(att_name.str, att_name.length);
                            
                            policy.oper.append(operator_str.str, operator_str.length);
                            
                            policy.right.append("O.");
                            policy.right.append(att_name.str, att_name.length);
                        }
                        else if(strncmp((char *)tag.str, "attvalconstval", tag.length) == 0)
                        {
                            policy.left.append("S.");
                            policy.left.append(att_name.str, att_name.length);
                            
                            policy.oper.append(operator_str.str, operator_str.length);
                            
                            policy.right.append(const_val.str, const_val.length);
                        }
                    }

                     if(policy.left.length() > 0 && policy.oper.length() >0 &&  policy.right.length() > 0)
                    {
                        Security_context *sctx = thd->security_context();
                        string my_ip = "localhost";
                        if (sctx->ip().str) my_ip = sctx->ip().str;

                        string u, obj;
                        u.clear();
                        obj.clear();
                        u.append(subject.str,subject.length);
                        obj.append(object.str,object.length);
                        int action = operation.str[0] -'0';
                        
                        policy.subject = u;
                        policy.object = obj;
                        policy.action = action;
                        

                        Acl_cache_lock_guard acl_cache_lock(thd, Acl_cache_lock_mode::READ_MODE);
                        if (!acl_cache_lock.lock()) return false;
                        int tmp_ans =  policy_decision(u,obj,&policy, my_ip);
                        //search 
                        vector<PPOLICY> list;
                        search_conf_policy(u, obj, action, list);
                        acl_cache_lock.unlock();

                        if (!acl_cache_lock.lock()) return false;
                        int state;
                        for (int i = 0; i < list.size(); i++)
                        {
                            int state = policy_decision(u,obj,list[i], my_ip);
                            if (state != tmp_ans)
                            {
                                acl_cache_lock.unlock();
                                string info;
                                info.append("policy conflict with: ");
                                info.append(list[i]->name);
                                info.append(", please set this policy unenable.");
                                //MEM_ROOT *mem_root= thd->mem_root;
                                mem_root_deque<Item *> field_list(thd->mem_root);
                                field_list.push_back(new Item_empty_string("result", 10));
                                Protocol *protocol = thd->get_protocol();
                                if (thd->send_result_metadata(field_list, Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
                                    return true; //DBUG_RETURN(true);
                                protocol->start_row();
                                protocol->store_string(info.c_str(), info.length(), system_charset_info);
                                if (protocol->end_row())
                                    return true; //DBUG_RETURN(true);
                                my_eof(thd);
                                reset_statement(thd);
                                return false;
                            }
                        }
                        acl_cache_lock.unlock();
                    }
                }
            }
        }
    }
    
    string command = "insert into mysql.abac_policies(subject,object,obj_typ,operation,policy_name,att_name,const_val,operator,tag,sub_att,obj_att,policy_enable) values('";
    command += subject.str;
    command += "','";
    command += object.str;
    command += "','";
    command += obj_typ.str;
    command += "',";
    command += operation.str;
    command += ",'";
    command += policy_name.str;
    command += "','"; 
    command += att_name.str;
    command += "',";

    if( const_val.length == 4 &&  strncmp(const_val.str,"null",4) == 0 ){ command += "null,'"; } 
    else { command += "\""; command += const_val.str; command += "\",'"; }

    command +=operator_str.str;
    command += "','";
    command +=tag.str;
    command += "',";
    command += sub_att.str; 
    command += ","; 
    command += obj_att.str; 
    command += ","; 
    command +=is_enable.str;
    command += ")";

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    //char buf[1024] ={0};

    int len = command.length()+5;
    char *buf = new char[len];
    memset(buf,0,len);


    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    res =  dispatch_command(thd, &cmd, COM_QUERY);
    delete[] buf;
    return res;
}

bool mysql_delete_policy(THD *thd,vector<LEX_STRING>& paramaters)
{
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }
    bool res;
    LEX_STRING policy_name = paramaters[0];

    string command = "delete from mysql.abac_policies where policy_name = '";
    command += policy_name.str;
    command += "'";

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    //char buf[150]={0};
    
    int len = command.length()+5;
    char *buf = new char[len];
    memset(buf,0,len);
    
    
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    res = dispatch_command(thd, &cmd, COM_QUERY);
    delete[] buf;
    return res;
}

bool show_all_policy(THD *thd)
{
    string command = "select * from mysql.abac_policies";

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    char buf[150]= {0};
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    return dispatch_command(thd, &cmd, COM_QUERY);
}

bool mysql_add_attribute(THD *thd,vector<LEX_STRING>& paramaters)
{
    bool res;
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }

    LEX_STRING id = paramaters[0];
    LEX_STRING name = paramaters[1];
    LEX_STRING type = paramaters[2];
    
    string command = "insert into mysql.abac_attributes values(";
    command += id.str;
    command += ",'";
    command += name.str;
    command += "','";
    command += type.str;
    command += "')";

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    
    //char buf[250] ={0};
    int len = command.length()+5;
    char *buf = new char[len];
    memset(buf,0,len);
   
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    res = dispatch_command(thd, &cmd, COM_QUERY);
    delete[] buf;
    return res;
}

bool mysql_delete_attribute(THD *thd,vector<LEX_STRING>& paramaters)
{
    bool res;
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }
    
    LEX_STRING attribute_name = paramaters[0];

    string command = "delete from mysql.abac_attributes where att_name = '";
    command += attribute_name.str;
    command += "'";

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    //char buf[150] = {0};
    
    int len = command.length()+5;
    char *buf = new char[len];
    memset(buf,0,len);

    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    res =  dispatch_command(thd, &cmd, COM_QUERY);
    delete[] buf;
    return res;
}

bool show_all_attributes(THD *thd)
{
    string command = "select * from mysql.abac_attributes";

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    char buf[150]= {0};
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    return dispatch_command(thd, &cmd, COM_QUERY);
}

bool mysql_add_attribute_manager(THD *thd,vector<LEX_STRING>& paramaters)
{
    bool res;
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }

    LEX_STRING attribute_name = paramaters[0];
    LEX_STRING attribute_value = paramaters[1];
    LEX_STRING object = paramaters[2];
    
    string command = "insert into mysql.abac_attribute_manager(object,att_name,attribute_value) values('";
    command += object.str;
    command += "','";
    command += attribute_name.str;
    command += "','";
    command +=  attribute_value.str;
    command += "')";

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    //char buf[300] ={0};
    int len = command.length()+5;
    char *buf = new char[len];
    memset(buf,0,len);
    
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    res =  dispatch_command(thd, &cmd, COM_QUERY);
    delete[] buf;
    return res;
}

bool mysql_delete_attribute_manager(THD *thd,vector<LEX_STRING>& paramaters)
{
    bool res;
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }
    LEX_STRING attribute_name = paramaters[0];
    LEX_STRING attribute_value = paramaters[1];
    LEX_STRING object = paramaters[2];

    string command = "delete from mysql.abac_attribute_manager where object= '";
    command += object.str;
    command += "' and attribute_value= '";
    command += attribute_value.str;
    command += "' and  att_name  = '";
    command += attribute_name.str;
    command += "'";

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    //char buf[300]={0};
    
    int len = command.length()+5;
    char *buf = new char[len];
    memset(buf,0,len);

    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    res =  dispatch_command(thd, &cmd, COM_QUERY);
    delete[] buf;
    return res;
}

bool show_all_attributes_manager(THD *thd)
{
    string command = "select * from mysql.abac_attribute_manager";

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    char buf[150] = {0};
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    return dispatch_command(thd, &cmd, COM_QUERY);
}

/**add by yuang in 20221005  end */


//单独增加一 domain_sec  
bool mysql_add_domain_sec(THD *thd,vector<LEX_STRING>& paramaters)
{
    bool res;
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }

    LEX_STRING domain_name = paramaters[0];
    string command = "insert into mysql.abac_domain_sec(domain_name) values('";
    command += domain_name.str;
    command += "')";
    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    
    //char buf[200] ={0};
    int len = command.length()+5;
    char *buf = new char[len];
    memset(buf,0,len);
    
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    res =  dispatch_command(thd, &cmd, COM_QUERY);
    delete[] buf;
    return res;
}

//单独增加一条 level_sec
bool mysql_add_level_sec(THD *thd,vector<LEX_STRING>& paramaters)
{
    bool res;
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }

    LEX_STRING level_name = paramaters[0];
    
    string command = "insert into mysql.abac_level_sec(level_name) values('";
    command += level_name.str;
    command += "')";
    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    
    //char buf[200] ={0};
    int len = command.length()+5;
    char *buf = new char[len];
    memset(buf,0,len);
    
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    res=  dispatch_command(thd, &cmd, COM_QUERY);
    delete[] buf;
    return res;
}


//单独删掉一条 level_sec  不能是 highest
bool mysql_delete_level_sec(THD *thd,vector<LEX_STRING>& paramaters)
{
    bool res;
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }
    
    LEX_STRING level_name = paramaters[0];
    if(strcmp(level_name.str,"highest") == 0)
    {
        send_cant_delete_level(thd);
        reset_statement(thd);
        return true;
    }
    
    string command = "delete from mysql.abac_level_sec where  level_name = '";
    command += level_name.str;
    command += "'";

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    
    //char buf[200] ={0};
    int len = command.length()+5;
    char *buf = new char[len];
    memset(buf,0,len);
    
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    res = dispatch_command(thd, &cmd, COM_QUERY);
    delete[] buf;
    return res;
}


// 单独删掉一条 domain_sec 不能是root
bool mysql_delete_domain_sec(THD *thd,vector<LEX_STRING>& paramaters)
{
    bool res;
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }

    LEX_STRING domain_name = paramaters[0];
    
    if(strcmp(domain_name.str,"root") == 0)
    {
        send_cant_delete_root(thd);
        reset_statement(thd);
        return true;
    }
    
    string command = "delete from mysql.abac_domain_sec where  domain_name = '";
    command += domain_name.str;
    command += "'";

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    //char buf[200] ={0};
    
    int len = command.length()+5;
    char *buf = new char[len];
    memset(buf,0,len);

    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    res = dispatch_command(thd, &cmd, COM_QUERY);
    delete[] buf;
    return res;
}


//在attribute_manager中增加一条记录c domain id 2
bool grant_domain_to_obj(THD *thd,vector<LEX_STRING>& paramaters)
{
    bool res;
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }
    
    LEX_STRING dom;
    LEX_STRING obj;

    dom = paramaters[0];
    obj = paramaters[1];
    
    string command = "insert into mysql.abac_attribute_manager(object,att_name,attribute_value) values('";
    command += obj.str;
    command += "',";
    command += "'domain','";
    command += dom.str;
    command += "')";


    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    //char buf[300] = {0};
    int len = command.length()+5;
    char *buf = new char[len];
    memset(buf,0,len);
    
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());
    
    res = dispatch_command(thd, &cmd, COM_QUERY);
    delete[] buf;
    return res;
}


bool grant_level_to_obj(THD *thd,vector<LEX_STRING>& paramaters)
{
    bool res;
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }
    
    LEX_STRING leve;
    LEX_STRING obj;

    leve = paramaters[0];
    obj = paramaters[1];
    
    string command = "insert into mysql.abac_attribute_manager(object,att_name,attribute_value) values('";
    command += obj.str;
    command += "',";
    command += "'level','";
    command += leve.str;
    command += "')";

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    //char buf[300] = {0};
    int len = command.length()+5;
    char *buf = new char[len];
    memset(buf,0,len);
    
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());
    
    res =  dispatch_command(thd, &cmd, COM_QUERY);
    delete[] buf;
    return res;
}



bool alter_policy_enable(THD *thd,vector<LEX_STRING>& paramaters)
{
    bool res;
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }
    
    LEX_STRING policy_name;

    policy_name = paramaters[0];
    
    string command = "update mysql.abac_policies set policy_enable = true where  policy_name = '";
    command += policy_name.str;
    command += "'";


    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    
    //char buf[300] = {0};
    int len = command.length()+5;
    char *buf = new char[len];
    memset(buf,0,len);
    
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());
    res =  dispatch_command(thd, &cmd, COM_QUERY);
    delete[] buf;
    return res;
}



bool alter_policy_disable(THD *thd,vector<LEX_STRING>& paramaters)
{
    bool res;
    if( !init )
    {
        send_access_deny(thd);
        reset_statement(thd);
        return true;
    }
    
    LEX_STRING policy_name;
    policy_name = paramaters[0];
    
    string command = "update mysql.abac_policies set policy_enable = false where  policy_name = '";
    command += policy_name.str;
    command += "'";

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    //char buf[300] = {0};
    int len = command.length()+5;
    char *buf = new char[len];
    memset(buf,0,len);
    
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());
    res =  dispatch_command(thd, &cmd, COM_QUERY);
    delete[] buf;
    return res;
}


int  close_abac(THD* thd)
{   //只有supervisor能开能关闭
    string priv_user = thd->security_context()->priv_user().str;
    string priv_host = thd->security_context()->priv_host().str;
    string sub = priv_user + "@" + priv_host;
    if ( sub != "abac_supervisor@%" && sub != "root@localhost")
    {
        send_access_deny(thd);  
        return false;
    }
    
    if( !init )
    {  
        my_ok(thd);
        return true;
    }
    else 
    {
        drop_domain_and_level();
        init = false;
        my_ok(thd);
        return false;
    }
}

//true:deny
bool check_abac_access_alter(THD *thd, List<LEX_USER> &list)
{
    if (!separation_of_powers_start)
        return false;
    
    Security_context *sctx = thd->security_context();
    string u = sctx->priv_user().str;
    string h = sctx->priv_host().str;
    string sub = u + "@" + h; 

    bool super = false;
    if(sub == "root@localhost") super = true;

    List_iterator<LEX_USER> user_list(list);
    LEX_USER *user;
    while ((user = user_list++) != nullptr) {
        if (strcmp(user->user.str, "abac_supervisor")==0 && strcmp(user->host.str,"%")==0 && sub != "abac_supervisor@%" ||
            strcmp(user->user.str, "abac_auditor")==0 && strcmp(user->host.str,"%")==0 && sub != "abac_auditor@%" ||
            strcmp(user->user.str, "abac_admin")==0 && strcmp(user->host.str,"%")==0 && sub != "abac_admin@%" || 
            strcmp(user->user.str, "root")==0 && strcmp(user->host.str,"localhost")==0 && sub != "root@localhost")
            {
                if(super) return false;
                my_error(ER_SEPARATION_OF_POWERS_DENIED_ERROR, MYF(0));
                return true;
            }
    }
    return false;
}

bool check_abac_access(THD *thd, List<LEX_USER> &list)
{
    if (!separation_of_powers_start)
        return false;
    
    Security_context *sctx = thd->security_context();
    string u = sctx->priv_user().str;
    string h = sctx->priv_host().str;
    string sub = u + "@" + h; 

    bool super = false;
    if(sub == "root@localhost") super = true;

    List_iterator<LEX_USER> user_list(list);
    LEX_USER *user;
    while ((user = user_list++) != nullptr) {
        if(strcmp(user->user.str, "root")==0 && strcmp(user->host.str,"localhost")==0) 
        {
            my_error(ER_UNKNOWN_ERROR, MYF(0), "You can't drop or rename the root@localhost user.");
            return true;
        }
        if (strcmp(user->user.str, "abac_supervisor")==0 && strcmp(user->host.str,"%")==0 ||
            strcmp(user->user.str, "abac_auditor")==0 && strcmp(user->host.str,"%")==0 ||
            strcmp(user->user.str, "abac_admin")==0 && strcmp(user->host.str,"%")==0 )
            {
                if(super) return false;
                my_error(ER_SEPARATION_OF_POWERS_DENIED_ERROR, MYF(0));
                return true;
            }
    }
    return false;
}


// return true 代表没过
bool check_sign(THD *thd, LEX_CSTRING db)
{
    if (!init)
    {
        return false;
    }

    Security_context *sctx = thd->security_context(); //从security_ctx变为security_context
    string u = sctx->priv_user().str;
    //feat-20230416:增加host判断, subject=user@host
        //priv_user@priv_host即为当前mysql所使用的用户条目
    string h = sctx->priv_host().str;
    string sub = u + "@" + h;       //后续用sub代替u
    //end feat
    if(sub == "root@localhost" || sub == "abac_supervisor@%"){
        return false;
    }
 
    string my_ip = "localhost";
    if (sctx->ip().str)
    {
        my_ip = sctx->ip().str; //以m_开头的参数是string类型
    }

    string str_db = db.str;
    // string obj = str_db + ".*"; // attribute_manager表中数据库用.*的方式表示
    string obj = str_db;
    int action = get_action(thd);


    //new added by yuang in 2022.9.26 公共内存上锁
    Acl_cache_lock_guard acl_cache_lock(thd, Acl_cache_lock_mode::READ_MODE);
    if (!acl_cache_lock.lock()) return true;

    vector<PPOLICY> list;
    search_policy(sub, obj, action, list);
    
    //new added by yuang in 2022.9.26 公共内存解锁
    acl_cache_lock.unlock();

    int state;

    if (list.size() == 0)
        return true;

    //new added by yuang in 2022.9.26 公共内存上锁
    if (!acl_cache_lock.lock()) return true;

    for (int i = 0; i < list.size(); i++)
    {
        state = policy_decision(sub,obj,list[i], my_ip);
        if (state == 0)
        {
            //new added by yuang in 2022.9.26 公共内存解锁
            acl_cache_lock.unlock();
            return true;
        }       
    }

    //new added by yuang in 2022.9.26 公共内存解锁
    acl_cache_lock.unlock();
    
    return false;
}

bool check_sign(THD *thd, LEX_CSTRING db, LEX_CSTRING table)
{
    if (!init)
    {
        return false;
    }

    //if (check_sign(thd, db))
    //  return true;

    Security_context *sctx = thd->security_context();

    string u = sctx->priv_user().str;
    //feat-20230416:增加host判断, subject=user@host
    string h = sctx->priv_host().str;
    string sub = u + "@" + h;       //后续用sub代替u
    //end feat
    if(sub == "root@localhost" || sub == "abac_supervisor@%"){
        return false;
    }

    string my_ip = "localhost";
    if (sctx->ip().str)
    {
        my_ip = sctx->ip().str;
    }

    string str_db = db.str;
    string str_table = table.str;
    string obj = str_db + "." + str_table;
    int action = get_action(thd);


    //new added by yuang in 2022.9.26 公共内存上锁
    Acl_cache_lock_guard acl_cache_lock(thd, Acl_cache_lock_mode::READ_MODE);
    if (!acl_cache_lock.lock()) return true;

    vector<PPOLICY> list;
    search_policy(sub, obj, action, list);

    //new added by yuang in 2022.9.26 公共内存解锁
    acl_cache_lock.unlock();

    int state;

    if (list.size() == 0)
        return true;

    //new added by yuang in 2022.9.26 公共内存上锁
    if (!acl_cache_lock.lock()) return true;

    for (int i = 0; i < list.size(); i++)
    {
        state = policy_decision(sub,obj,list[i], my_ip);
        if (state == 0)
        {
            //new added by yuang in 2022.9.26 公共内存解锁
            acl_cache_lock.unlock();
            return true;
        }       
    }
    return false;
}

bool check_sign(THD* thd, LEX_CSTRING db, LEX_CSTRING table, LEX_CSTRING col_name)
{
    if (!init)
    {
        return false;
    }

   // if (check_sign(thd, db, table))
   //     return true;

    Security_context *sctx = thd->security_context();

    string u = sctx->priv_user().str;
    //feat-20230416:增加host判断, subject=user@host
    string h = sctx->priv_host().str;
    string sub = u + "@" + h;       //后续用sub代替u
    //end feat
    if(sub == "root@localhost" || sub == "abac_supervisor@%"){
        return false;
    }

    string my_ip = "localhost";
    if (sctx->ip().str)
    {
        my_ip = sctx->ip().str;
    }

    string str_db = db.str;
    string str_table = table.str;
    string str_col_name = col_name.str;
    string obj = str_db + "." + str_table+"."+str_col_name;
    int action = get_action(thd);


    //new added by yuang in 2022.9.26 公共内存上锁
    Acl_cache_lock_guard acl_cache_lock(thd, Acl_cache_lock_mode::READ_MODE);
    if (!acl_cache_lock.lock()) return true;

    vector<PPOLICY> list;
    search_policy(sub, obj, action, list);

    //new added by yuang in 2022.9.26 公共内存解锁
    acl_cache_lock.unlock();

    int state;
    if (list.size() == 0)
        return true;

    //new added by yuang in 2022.9.26 公共内存上锁
    if (!acl_cache_lock.lock()) return true;

    for (int i = 0; i < list.size(); i++)
    {
        state = policy_decision(sub,obj,list[i], my_ip);
        if (state == 0)
        {
            //new added by yuang in 2022.9.26 公共内存解锁
            acl_cache_lock.unlock();
            return true;
        }
    }
    return false;
}

bool create_user_and_att(THD *thd,vector<LEX_STRING>& paramaters)
{
    // my_error(ER_UNABLE_TO_SET_OPTION, MYF(0),base64_utils::_base64);
    LEX_STRING user_name = paramaters[0];
    LEX_STRING user_host = paramaters[1];
    LEX_STRING passwd = paramaters[2];
    LEX_STRING att_list = paramaters[3];
    string command1 = "create user '";
    command1 += user_name.str;
    command1 += "'@'";
    command1 += user_host.str;
    command1 += "' identified by '";
    command1 += passwd.str;
    command1 += "'";
    string command2 = "insert into mysql.abe_attribute_manager(user, att) values('";
    command2 += user_name.str;
    command2 += "@";
    command2 += user_host.str;
    command2 += "','";
    command2 += att_list.str;
    command2 += "')";
    command1 = command1 + ";" + command2;
    COM_DATA cmd1;
    memset(&cmd1, 0, sizeof(cmd1));

    //char buf[200] ={0};
    int len1 = command1.length()+5;
    char *buf1 = new char[len1];
    memset(buf1,0,len1);

    strcpy(buf1, command1.c_str());
    cmd1.com_query.query = reinterpret_cast<const char *>(buf1);
    cmd1.com_query.length = static_cast<unsigned int>(command1.length());

    bool res1 =  dispatch_command(thd, &cmd1, COM_QUERY);
    delete[] buf1;
    return res1;
}

bool grant_abe_att(THD *thd,vector<LEX_STRING>& paramaters)
{
    LEX_STRING att_list = paramaters[0];
    LEX_STRING user_name = paramaters[1];
    LEX_STRING user_host = paramaters[2];
    string namehost = user_name.str + string("@") + user_host.str;
    string command1 = "insert into mysql.abe_attribute_manager(user, att) values('";
    command1 += namehost;
    command1 += "','";
    command1 += att_list.str;
    command1 += "')";
    
    //和KMS通信，获取abe密钥，构造插入语句
    string add_abe_key_command = initAbeData(namehost,att_list.str);

    string command = command1 + ";" + add_abe_key_command;

    COM_DATA cmd;
    memset(&cmd, 0, sizeof(cmd));
    int len = command.length()+5;
    char *buf = new char[len];
    memset(buf,0,len);
    
    strcpy(buf, command.c_str());
    cmd.com_query.query = reinterpret_cast<const char *>(buf);
    cmd.com_query.length = static_cast<unsigned int>(command.length());

    bool res =  dispatch_command(thd, &cmd, COM_QUERY);
    delete[] buf;
    return res;
}