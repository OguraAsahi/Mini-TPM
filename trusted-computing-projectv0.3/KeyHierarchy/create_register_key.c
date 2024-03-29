#include "common.h"

TSS_RESULT
my_create_key(TSS_HCONTEXT hContext, TSS_FLAG initFlags, TSS_HKEY hParent, TSS_HKEY *hKey, const char *pName);

/* create and load a key off the parentKey */
TSS_RESULT
my_create_load_key(TSS_HCONTEXT hContext, TSS_FLAG initFlags,
				TSS_HKEY hParent, TSS_HKEY *hKey, const char *pName);

char *key_structure = "SRK\n"
		      "|__UserK1(Storage key, unmigratable)\n"
		      "|  |__UserK2(Signing key, unmigratable)\n"
		      "|\n"
                      "|__UserK3(Storage key, migratable)\n"
		      "   |__UserK4(Bind key, migratable)\n";

TSS_UUID UUID_K1 =  {0, 0, 0, 0, 0, {8, 0, 0, 0, 0, 1}} ;
TSS_UUID UUID_K2 = {0, 0, 0, 0, 0, {8, 0, 0, 0, 0, 2}} ;
TSS_UUID UUID_K3 = {0, 0, 0, 0, 0, {8, 0, 0, 0, 0, 3}} ;
TSS_UUID UUID_K4 = {0, 0, 0, 0, 0, {8, 0, 0, 0, 0, 4}} ;

int main(int argc, char **argv)
{
	char version;

	version = parseArgs(argc, argv);
	if (version)
		main_v1_1();
	else
		print_wrongVersion();
}

main_v1_1(void)
{

	char *nameOfFunction = "Create KEY";
	TSS_HCONTEXT hContext;
	TSS_HTPM hTPM;
	TSS_FLAG initFlags;
	TSS_HKEY hKey1, hKey2, hKey3, hKey4, hKeyTmp;
	TSS_HKEY hSRK;
	TSS_RESULT result;
	TSS_HPOLICY srkUsagePolicy, keyUsagePolicy;
	TSS_HPOLICY hPolicy, tpmUsagePolicy;

	print_begin_test(nameOfFunction);
	printf("KEY structure:\n%s\n", key_structure);//全局字符串 展示密钥结构

	//Create Context
	result = Tspi_Context_Create(&hContext);//创建上下文环境, 上下文由句柄变量hContext保存
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
	//Connect Context
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));//连接TPM和上下文环境
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	
	//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext,
					    TSS_PS_TYPE_SYSTEM, SRK_UUID,
					    &hSRK);//通过UUID加载秘钥, 存于hSRK
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
#ifndef TESTSUITE_NOAUTH_SRK
	//Get Policy Object
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);//获得SRK策略，存于srkUsagePolicy
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Set Secret
	result = Tspi_Policy_SetSecret(srkUsagePolicy,//设置SRK的授权密钥
				  TESTSUITE_SRK_SECRET_MODE,
				  TESTSUITE_SRK_SECRET_LEN,
				  TESTSUITE_SRK_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
#endif
	// fist unregister keys  注销密钥, 防止秘钥重复注册, 在生成秘钥层次前会把之前的秘钥注销
	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM,
					UUID_K1,
					&hKeyTmp );
	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM,
					UUID_K2,
					&hKeyTmp );
	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM,
					UUID_K3,
					&hKeyTmp );
	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM,
					UUID_K4,
					&hKeyTmp );
					
	//Create K1, parent key is SRK
	printf("Create UserK1 and register it to disk.\n");
	initFlags = TSS_KEY_TYPE_STORAGE | TSS_KEY_SIZE_2048 |
	    TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION |
	    TSS_KEY_NOT_MIGRATABLE;//重要   存储密钥，2048位，可变密钥，授权密钥，不可迁移密钥,init位传递了秘钥的信息
    
    //检查秘钥句柄对应的秘钥是否存在,若存在则调用load, 不存在则调用create, 由于上面已经注销, 所以默认为生成秘钥
	result = my_create_load_key(hContext, initFlags, hSRK, &hKey1, "K1");//创建K1，上下文，标志位，父密钥，存于哪里，名字
	if (result != TSS_SUCCESS) {
		print_error("create_key", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	
	// Register K1
	result = Tspi_Context_RegisterKey(hContext, hKey1,
						   TSS_PS_TYPE_SYSTEM,
						   UUID_K1,
						   TSS_PS_TYPE_SYSTEM,
						   SRK_UUID);//注册密钥，上下文，存于哪里，SYSTEM参数，UUID，SYSTEM参数，父密钥的UUID
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_RegisterKey", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	printf("Create and register K1 successed!\n");

	// Create K2, parent key is K1
	printf("Create UserK2 and register it to disk.\n");
	initFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 |
	    		TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION |
	    		TSS_KEY_NOT_MIGRATABLE;
	result = my_create_load_key(hContext, initFlags, hKey1, &hKey2, "K2");
	if (result != TSS_SUCCESS) {
		print_error("create_key", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Context_RegisterKey(hContext, hKey2,
						   TSS_PS_TYPE_SYSTEM,
						   UUID_K2,
						   TSS_PS_TYPE_SYSTEM,
						   UUID_K1);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_RegisterKey", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	printf("Create and register K2 successed!\n");
	
	// K3  , migratable, parent key is SRK
	printf("Create UserK3 and register it to disk.\n");
	initFlags = TSS_KEY_TYPE_STORAGE | TSS_KEY_SIZE_2048 |
	    		TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION |
	    		TSS_KEY_MIGRATABLE;
	result = my_create_load_key(hContext, initFlags, hSRK, &hKey3,"K3");
	if (result != TSS_SUCCESS) {
		print_error("create_key", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Context_RegisterKey(hContext, hKey3,
						   TSS_PS_TYPE_SYSTEM,
						   UUID_K3,
						   TSS_PS_TYPE_SYSTEM,
						   SRK_UUID);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_RegisterKey", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	printf("Create and register K3 successed!\n");

	// K4  , migratable , parent key is K3
	// TODO:
	// 这部分由同学们来完成
	// 
	printf("Create UserK4 and register it to disk.\n");
	initFlags = TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048 |
	    		TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION |
	    		TSS_KEY_MIGRATABLE;//绑定密钥，2048位，可变密钥，授权密钥，可迁移密钥
	result = my_create_load_key(hContext, initFlags, hKey3, &hKey4,"K4");//创建K4，上下文，标志位，父密钥，存于哪里，名字
	if (result != TSS_SUCCESS) {
		print_error("create_key", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Context_RegisterKey(hContext, hKey4,
						   TSS_PS_TYPE_SYSTEM,
						   UUID_K4,
						   TSS_PS_TYPE_SYSTEM,
						   UUID_K3);//注册密钥，上下文，存于哪里，SYSTEM参数，UUID，SYSTEM参数，父密钥的UUID
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_RegisterKey", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	
	printf("Create and register K4 successed!\n");
	
	// Unload keys, pay attention to the order, child key must unload first
	result = Tspi_Key_UnloadKey( hKey2 );
	result = Tspi_Key_UnloadKey( hKey1 );
	result = Tspi_Key_UnloadKey( hKey4 );
	result = Tspi_Key_UnloadKey( hKey3 );
	
	if (result != TSS_SUCCESS) {
		if (!checkNonAPI(result)) {
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_Close(hContext);
			exit(result);
		} else {
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_Close(hContext);
			exit(result);
		}
	} else {
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}

/* create a key off the parentKey */
TSS_RESULT my_create_key(TSS_HCONTEXT hContext, TSS_FLAG initFlags, TSS_HKEY hParent, TSS_HKEY *hKey, const char *pName)
{
	TSS_RESULT result;
	TSS_HPOLICY hPolicy, hPolicyMigrate;
	char *prompt[256];

		//Create Object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		return(result);
	}

	if (initFlags & TSS_KEY_AUTHORIZATION) {  //设置授权策略
		//printf("Seting secret...\n");
		sprintf(prompt, "Input %s's Usage Pin", pName);
		if ((result = set_popup_secret(hContext, *hKey, TSS_POLICY_USAGE, prompt, 1)))
			return result;
		/*if ((result = set_secret(hContext, *hKey, &hPolicy)))
			return result;*/
	}
	if (initFlags & TSS_KEY_MIGRATABLE)  //设置迁移策略
	{
		printf("^^migratable\n");
		sprintf(prompt, "%s's Migration Pin", pName);
		if ((result = set_popup_secret(hContext, *hKey, TSS_POLICY_MIGRATION, prompt, 1)))
			return result;
		/*result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
					TSS_POLICY_MIGRATION, &hPolicyMigrate);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Context_CreateObject", result);
			Tspi_Context_Close(hContext);
			exit(result);
		}
		//Set Secret
		result = Tspi_Policy_SetSecret( hPolicyMigrate, TESTSUITE_KEY_SECRET_MODE,
					       TESTSUITE_KEY_SECRET_LEN,
					       TESTSUITE_KEY_SECRET);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Policy_SetSecret", result);
			Tspi_Context_Close(hContext);
			exit(result);
		}
		//Assign migration policy to the key
		result = Tspi_Policy_AssignToObject( hPolicyMigrate, *hKey);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Policy_AssignToObject", result);
			Tspi_Context_Close(hContext);
			exit(result);
		}*/

	}

	//CreateKey
	result = Tspi_Key_CreateKey(*hKey, hParent, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		return(result);
	}

	return TSS_SUCCESS;
}

/* create and load a key off the parentKey */
TSS_RESULT
my_create_load_key(TSS_HCONTEXT hContext, TSS_FLAG initFlags,
		TSS_HKEY hParent, TSS_HKEY *hKey, const char *pName)
{
	TSS_RESULT result;

	if ((result = my_create_key(hContext, initFlags, hParent, hKey, pName)))
		return result;

	result = Tspi_Key_LoadKey(*hKey, hParent);
        if (result != TSS_SUCCESS) {
                print_error("Tspi_Key_LoadKey", result);
                return(result);
        }

	return TSS_SUCCESS;
}


