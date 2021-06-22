/**
 * @file seal_file.c
 * @author WangFengwei Email: 110.visual@gmail.com
 * @brief seal a file
 * @created 2011-06-19
 * @modified
 
 * 将秘密信息绑定TPM特定的PCR值来实现保护, 只有当PCR满足特定值时才能解封, 一旦Extend就会解封失败
 * 我们要做的是从密文文件中提取对称秘钥并解密密文,将明文写入到文件当中
 * 根据封装和加密的过程,构造其逆过程,根据aes_encrypt构造aes_decrypt, TPM初始化部分不变, 无需获取PCR的值
 */

#include "common.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx)
{
  int i, nrounds = 5;
  unsigned char key[32], iv[32];
  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }
  EVP_CIPHER_CTX_init(e_ctx);
  EVP_DecryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  return 0;
}
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  unsigned char *ciphertext = malloc(c_len);
	EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(e, ciphertext, &c_len, plaintext, *len);
	EVP_DecryptFinal_ex(e, ciphertext+c_len, &f_len);
  *len = c_len + f_len;
  return ciphertext;
}

void usage(char *pch_name)
{
	printf("Usage: %s source destination\n", pch_name);
	printf("eg: %s plaintext_file cipertext_file\n", pch_name);
}
int main(int argc, char **argv)
{

#define BUF_LEN	(1024*1024)
#define KEY_SIZE 64
	TSS_RESULT result;
	TSS_HCONTEXT hContext;
	TSS_HKEY hSRK, hKey;
	TSS_HPOLICY hPolicy;
	TSS_HTPM hTPM;
	TSS_HENCDATA hEncData;
	TSS_HPCRS hPcrs;
	UINT32 DataSealedLen,DataUnsealedLen;//DataSealedLen是Seal的密钥长度从文件读取，DataUnsealedLen是解封之后密钥的长度
	BYTE *DataUnsealed,*DataSealed,*dataBuf;//DataUnsealed就是对称密钥random，DataSealed是从文件读取的
	FILE *fpIn = NULL, *fpOut = NULL;
	int len, size;//len是fread读取到的长度，size是文件实际大小
	char *pBufIn = NULL, *pBufOut = NULL;
	unsigned int salt[] = {12345, 54321};
	EVP_CIPHER_CTX de;
	TSS_UUID UUID_K1 =  {0, 0, 0, 0, 0, {8, 0, 0, 0, 0, 1}} ;

	if (argc < 3) {
		usage(argv[0]);
		return 0;
	}

	result = Tspi_Context_Create(&hContext);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Context_Create", result);
		Tspi_Context_Close(hContext);
		return result;
	}

	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Context_Connect", result);
		Tspi_Context_Close(hContext);
		return result;
	}

	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Context_GetTpmObject", result);
		Tspi_Context_Close(hContext);
		return result;
	}

	result = Tspi_Context_LoadKeyByUUID(hContext, 
					TSS_PS_TYPE_SYSTEM, 
					SRK_UUID, 
					&hSRK);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Context_LoadKeyByUUID", result);
		Tspi_Context_Close(hContext);
		return result;
	}

#ifndef TESTSUITE_NOAUTH_SRK
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hPolicy);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_GetPolicyObject", result);
		Tspi_Context_Close(hContext);
		return result;
	}

	result = Tspi_Policy_SetSecret(hPolicy, 
						TESTSUITE_SRK_SECRET_MODE, 
						TESTSUITE_SRK_SECRET_LEN, 
						TESTSUITE_SRK_SECRET);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Policy_SetSecret", result);
		Tspi_Context_Close(hContext);
		return result;
	}
#endif // #ifndef TESTSUITE_NOAUTH_SRK

	result = Tspi_Context_CreateObject(hContext, 
						TSS_OBJECT_TYPE_PCRS, 
						0, 
						&hPcrs);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		return result;
	}

	result = Tspi_Context_CreateObject(hContext, 
						TSS_OBJECT_TYPE_ENCDATA, 
						TSS_ENCDATA_SEAL, 
						&hEncData);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		return result;
	}

	result = set_secret(hContext, hEncData, &hPolicy);
	if (TSS_SUCCESS != result) {
		print_error("set_secret", result);
		Tspi_Context_Close(hContext);
		return result;
	}						

	result = Tspi_Context_LoadKeyByUUID(hContext, 
						TSS_PS_TYPE_SYSTEM, 
						UUID_K1, 
						&hKey);
	if (TSS_SUCCESS != result) {
		print_error("Tspi_Context_LoadKeyByUUID", result);
		Tspi_Context_Close(hContext);
		return -1;
	}

	result = set_popup_secret(hContext, 
						hKey, 
						TSS_POLICY_USAGE, 
						"Input K1's Pin\n", 
						0);
	if (TSS_SUCCESS != result) {
		print_error("set_popup_secret", result);
		Tspi_Context_Close(hContext);
		return result;
	}
	/********************** 读文件 获得相关数据 *************************************/
	fpIn = fopen(argv[1], "rb");
	if (!fpIn) {
		printf("open %s failed\n", argv[1]);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(-1);
	}
	if (fread(&DataSealedLen,1,sizeof(UINT32), fpIn) != sizeof(UINT32))//获得Sealed的密钥长度
	{
		printf("fread failed in lenth of sealed data\n");
		fclose(fpIn);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(-1);
	}
	DataSealed = (BYTE *)malloc(DataSealedLen);
	if (fread(DataSealed ,1, DataSealedLen, fpIn) != DataSealedLen)//获得Sealed的密钥
	{
		printf("fread failed in getting sealed data\n");
		free(DataSealed);
		fclose(fpIn);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(-1);
	}
	if (fread(&size,1,sizeof(int), fpIn) != sizeof(int))//获得文件长度
	{
		printf("fread failed in size of file\n");
		fclose(fpIn);
		free(DataSealed);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(-1);
	}
	pBufIn = (char *)malloc(size);
	if (fread(pBufIn,1,size, fpIn) != size)//获得加密的文件数据
	{
		printf("fread failed getting data of file\n");
		fclose(fpIn);
		free(DataSealed);
		free(pBufIn);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(-1);
	}
	fclose(fpIn);
	/*************************** 读文件结束 *************************************/
	
	result = Tspi_SetAttribData(hEncData,
				TSS_TSPATTRIB_ENCDATA_BLOB,
				TSS_TSPATTRIB_ENCDATABLOB_BLOB,
				DataSealedLen,
				DataSealed); //调用SetAttributeData将封装的秘密数据读取出来, 获取秘密数据句柄hEncData
	if (TSS_SUCCESS != result) {
		print_error("Tspi_SetAttribData", result);
		free(DataSealed);
		DataSealed = NULL;
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
					
	result = Tspi_Data_Unseal(hEncData,
				hKey,
				&DataUnsealedLen,
				&DataUnsealed); //调用Unseal将hEncData解封, 若PCR状态满足则成功, 解封的数据长度由DataUnsealedLen保存, 内容存于DataUnsealed
	printf("Unsealed Data:\n");
	print_hex(DataUnsealed, DataUnsealedLen);//获得了AES密钥
	
	if (aes_init(DataUnsealed, KEY_SIZE, (unsigned char *)&salt, &de)) {//DataUnsealed是AES的密钥，salt是盐值
		printf("aes_init failed\n");
		Tspi_Context_Close(hContext);
		free(pBufIn);
		return -1;
	}
	pBufOut = (char * )malloc(size);
	pBufOut = aes_decrypt(&de, pBufIn, &size);//pBufOut是加密文件数据
	
	/************************  开始写入文件 *****************************/
	fpOut = fopen(argv[2], "wb");
	if (!fpOut) {
		printf("open file: %s failed\n", argv[2]);
		Tspi_Context_Close(hContext);
		free(pBufIn);
		free(pBufOut);
		return -1;
	}
	len = fwrite(pBufOut, 1, size, fpOut);
	if (len != size) {
		printf("fwrite failed\n");
		Tspi_Context_Close(hContext);
		free(pBufIn);
		free(pBufOut);
		fclose(fpOut);
		return -1;
	}
	/************************  写文件结束 *****************************/
	fclose(fpOut);
	free(pBufIn);
	free(pBufOut);

	Tspi_Context_Close(hContext);

	return 0;
	
}
