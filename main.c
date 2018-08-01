/*
 * Copyright (c) 2016 NSR (National Security Research Institute)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"), to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
 * copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN 
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include "include/drbg.h"
#include "include/hmac_drbg.h"

#define MAX_FILE_NAME_LEN 256
#define MAX_READ_LEN 3072
#define MAX_DATA_LEN 1000001	// original 256 * 4

#pragma warning(disable: 4996)

void drbg_lsh_test_drive()
{
	FILE *input_file, *output_file;
	char input_file_name[MAX_FILE_NAME_LEN], output_file_name[MAX_FILE_NAME_LEN];
	lsh_u8 read_line[MAX_DATA_LEN];

	lsh_u8 drbg_result[LSH512_HASH_VAL_MAX_BYTE_LEN];

	lsh_type algtype;
	lsh_u8 entropy[3][64];
	lsh_u8 nonce[32];
	lsh_u8 per_string[64];
	lsh_u8 add_input[2][64];
	lsh_uint output_bits = 512;
	lsh_uint reseed_cycle = 1;

	int entropy_size	= 32;
	int nonce_size		= 16;
	int per_size		= 32;
	int add_size		= 32;

	sprintf(input_file_name, "test_data/Hash_DRBG_LSH-256-256.txt");
	input_file = fopen(input_file_name, "r");

	sprintf(output_file_name, "test_data/Hash_DRBG_LSH-256-256_rsp.txt");
	output_file = fopen(output_file_name, "w");

	algtype = LSH_TYPE_256_256;

	if(input_file != NULL)
	{
		fgets(read_line, MAX_READ_LEN, input_file);	// remove first line
		fgets(read_line, MAX_READ_LEN, input_file);	// remove second line
		fgets(read_line, MAX_READ_LEN, input_file);	// read entropy1
		for(int r = 11, w = 0 ; r < entropy_size * 2 + 10; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			entropy[0][w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read entropy2
		for(int r = 11, w = 0 ; r < entropy_size * 2 + 10; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			entropy[1][w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read entropy3
		for(int r = 11, w = 0 ; r < entropy_size * 2 + 10; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			entropy[2][w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read nonce
		for(int r = 8, w = 0 ; r < nonce_size * 2 + 8; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			nonce[w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read perstring
		for(int r = 12, w = 0 ; r < entropy_size * 2 + 12; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			per_string[w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read addinput1
		for(int r = 12, w = 0 ; r < entropy_size * 2 + 12; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			add_input[0][w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read addinput2
		for(int r = 12, w = 0 ; r < entropy_size * 2 + 12; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			add_input[1][w++] = strtol(str_to_hex, NULL, 16);
		}

		fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-256_256 \n\n");	//output text
		fprintf(output_file, "entropy = ");
		for(int i = 0 ; i < entropy_size ; i++)
			fprintf(output_file, "%02x", entropy[0][i]);
		fprintf(output_file, "\n");
		fprintf(output_file, "nonce = ");
		for(int i = 0 ; i < nonce_size ; i++)
			fprintf(output_file, "%02x", nonce[i]);
		fprintf(output_file, "\n");
		fprintf(output_file, "perString = ");
		for(int i = 0 ; i < per_size ; i++)
			fprintf(output_file, "%02x", per_string[i]);
		fprintf(output_file, "\n\n");


		drbg_lsh_digest(algtype, entropy, entropy_size, nonce, nonce_size, per_string, per_size, add_input, add_size, output_bits, reseed_cycle, drbg_result, output_file);
	}
	else
	{
		printf("file does not exist");
		return ;
	}

	printf("DRBG Finished \n");

	fclose(input_file);
	fclose(output_file);
}

void hmac_drbg_lsh_test_drive()
{
	FILE *input_file, *output_file;
	char input_file_name[MAX_FILE_NAME_LEN], output_file_name[MAX_FILE_NAME_LEN];
	lsh_u8 read_line[MAX_DATA_LEN];

	lsh_u8 hmac_drbg_result[128];

	lsh_type algtype;
	lsh_u8 entropy[3][64];
	lsh_u8 nonce[32];
	lsh_u8 per_string[64];
	lsh_u8 add_input[2][64];
	lsh_uint output_bits = 512;
	lsh_uint reseed_cycle = 1;

	int entropy_size	= 32;
	int nonce_size		= 16;
	int per_size		= 32;
	int add_size		= 32;

	sprintf(input_file_name, "HMAC_DRBG_test/reference/HMAC_DRBG_LSH-256-256(no PR).txt");
	input_file = fopen(input_file_name, "r");

	sprintf(output_file_name, "HMAC_DRBG_test/reference/HMAC_DRBG_LSH-256-256(no PR)_rsp.txt");
	output_file = fopen(output_file_name, "w");
	fprintf(output_file, "Algo_ID = HMAC_DRBG_LSH-256_256 \n\n");

	printf("test data from: %s \n", input_file_name);

	algtype = LSH_TYPE_256_256;

	if(input_file != NULL)
	{
		fgets(read_line, MAX_READ_LEN, input_file);	// remove first line
		fgets(read_line, MAX_READ_LEN, input_file);	// remove second line
		fgets(read_line, MAX_READ_LEN, input_file);	// read entropy1
		for(int r = 11, w = 0 ; r < entropy_size * 2 + 10; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			entropy[0][w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read entropy2
		for(int r = 11, w = 0 ; r < entropy_size * 2 + 10; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			entropy[1][w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read entropy3
		for(int r = 11, w = 0 ; r < entropy_size * 2 + 10; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			entropy[2][w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read nonce
		for(int r = 8, w = 0 ; r < nonce_size * 2 + 8; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			nonce[w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read perstring
		for(int r = 12, w = 0 ; r < entropy_size * 2 + 12; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			per_string[w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read addinput1
		for(int r = 12, w = 0 ; r < entropy_size * 2 + 12; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			add_input[0][w++] = strtol(str_to_hex, NULL, 16);
		}

		fgets(read_line, MAX_READ_LEN, input_file);	// read addinput2
		for(int r = 12, w = 0 ; r < entropy_size * 2 + 12; r += 2)
		{
			lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
			add_input[1][w++] = strtol(str_to_hex, NULL, 16);
		}

		//output text
		fprintf(output_file, "entropy = ");
		for(int i = 0 ; i < entropy_size ; i++)
			fprintf(output_file, "%02x", entropy[0][i]);
		fprintf(output_file, "\n");
		fprintf(output_file, "nonce = ");
		for(int i = 0 ; i < nonce_size ; i++)
			fprintf(output_file, "%02x", nonce[i]);
		fprintf(output_file, "\n");
		fprintf(output_file, "perString = ");
		for(int i = 0 ; i < per_size ; i++)
			fprintf(output_file, "%02x", per_string[i]);
		fprintf(output_file, "\n\n");


		hmac_drbg_lsh_digest(algtype, entropy, entropy_size, nonce, nonce_size, per_string, per_size, add_input, add_size, output_bits, reseed_cycle, hmac_drbg_result, output_file);
	}
	else
	{
		printf("file does not exist");
		return ;
	}

	printf("HMAC DRBG Finished \n");

	fclose(input_file);
	fclose(output_file);
}

void drbg_lsh_testvector_pr()
{
	FILE *input_file, *output_file;
	char input_file_name[MAX_FILE_NAME_LEN], output_file_name[MAX_FILE_NAME_LEN];
	lsh_u8 drbg_result[128];

	lsh_u8 read_line[MAX_DATA_LEN];

	lsh_type algtype;
	lsh_u8 entropy[256];
	lsh_u8 entropy_pr1[256];
	lsh_u8 entropy_pr2[256];
	lsh_u8 nonce[256];
	lsh_u8 per_string[256];
	lsh_u8 add_input1[256];
	lsh_u8 add_input2[256];

	bool prediction_resistance;
	lsh_uint output_bits;

	lsh_uint reseed_cycle = 1;

	int entropy_size = 0;
	int nonce_size = 0;
	int per_size = 0;
	int add_size = 0;
	int count;

	int r, w;
	lsh_u8 *str_to_int;

	int is, os;
	int is_ary[2] = {256, 512};
	int os_ary[4] = {224, 256, 384, 512};

	for(is = 0, os = 0 ; os < 4 ; os++)
	{
		if(is == 0 && os == 2)
		{
			is = 1;
			os = -1;
			continue;
		}
		sprintf(input_file_name, "DRBG_test/testvector/HASH_DRBG(LSH-%d_%d(-)(PR))_KAT_req.txt", is_ary[is], os_ary[os]);
		sprintf(output_file_name, "DRBG_test/testvector/HASH_DRBG(LSH-%d_%d(-)(PR))_KAT_rsp.txt", is_ary[is], os_ary[os]);
		input_file = fopen(input_file_name, "r");
		output_file = fopen(output_file_name, "w");

		if(input_file == NULL)
		{
			printf("file does not exist \n");
			return;
		}
		else
			printf("test data from: %s \n", input_file_name);

		for(int i = 0 ; i < 4 ; i++)
		{
			fgets(read_line, MAX_READ_LEN, input_file);	// read algtype
			read_line[strlen(read_line) - 1] = '\0';

			if(!strcmp(read_line, "[LSH-256_224]"))
			{
				output_bits = 448;
				algtype = LSH_TYPE_256_224;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-256_224\n");
			}
			else if(!strcmp(read_line, "[LSH-256_256]"))
			{
				output_bits = 512;
				algtype = LSH_TYPE_256_256;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-256_256\n");
			}
			else if(!strcmp(read_line, "[LSH-512_224]"))
			{
				output_bits = 448;
				algtype = LSH_TYPE_512_224;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_224\n");
			}
			else if(!strcmp(read_line, "[LSH-512_256]"))
			{
				output_bits = 512;
				algtype = LSH_TYPE_512_256;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_256\n");
			}
			else if(!strcmp(read_line, "[LSH-512_384]"))
			{
				output_bits = 768;
				algtype = LSH_TYPE_512_384;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_384\n");
			}
			else if(!strcmp(read_line, "[LSH-512_512]"))
			{
				output_bits = 1024;
				algtype = LSH_TYPE_512_512;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_512\n");
			}
			else
			{
				printf("unknown algorithm type \n");
				return;
			}

			fgets(read_line, MAX_READ_LEN, input_file);	// read PR
			read_line[strlen(read_line) - 1] = '\0';
			if(!strcmp(read_line, "[PredictionResistance = True]"))
			{
				prediction_resistance = true;
				fprintf(output_file, "PredictionResistance = True\n");
				printf("Prediction Resistance: True \n");
			}
			else if(!strcmp(read_line, "[PredictionResistance = False]"))
			{
				prediction_resistance = false;
				fprintf(output_file, "PredictionResistance = False\n");
				printf("Prediction Resistance: false \n");
			}
			else
			{
				printf("unknown prediction resistance setting \n");
				return;
			}

			fgets(read_line, MAX_READ_LEN, input_file);	// read entropy length
			str_to_int = &read_line[19];
			entropy_size = atoi(str_to_int);
			fprintf(output_file, "EntropyInputLen = %d\n", entropy_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// read nonce length
			str_to_int = &read_line[11];
			nonce_size = atoi(str_to_int);
			fprintf(output_file, "NonceLen = %d\n", nonce_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// read persnalization length
			str_to_int = &read_line[27];
			per_size = atoi(str_to_int);
			fprintf(output_file, "PersonalizationStringLen = %d\n", per_size);

			fgets(read_line, MAX_READ_LEN, input_file); // read additional length
			str_to_int = &read_line[21];
			add_size = atoi(str_to_int);
			fprintf(output_file, "AdditionalInputLen = %d\n\n", add_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// skip line

			while(count != 14)
			{
				fgets(read_line, MAX_READ_LEN, input_file);	// get count
				str_to_int = &read_line[8];
				count = atoi(str_to_int);

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy
				for(r = 15, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get nocne
				for(r = 8, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					nonce[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file); // get personalization string
				if(per_size)
				{
					for(r = 24, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						per_string[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get additional input1
				if(add_size)
				{
					for(r = 18, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						add_input1[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy pr1
				for(r = 17, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy_pr1[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get additional input2
				if(add_size)
				{
					for(r = 18, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						add_input2[w++] = strtol(str_to_hex, NULL, 16);
					}
				}


				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy pr2
				for(r = 17, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy_pr2[w++] = strtol(str_to_hex, NULL, 16);
				}
				fgets(read_line, MAX_READ_LEN, input_file);	// skip line

				drbg_lsh_testvector_pr_digest(algtype, prediction_resistance, entropy, entropy_pr1, entropy_pr2, entropy_size, nonce, nonce_size, per_string, per_size, add_input1, add_input2, add_size, output_bits, reseed_cycle, drbg_result);

				fprintf(output_file, "COUNT = %d\n", count);
				fprintf(output_file, "EntropyInput = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy[i]);
				fprintf(output_file, "\nNonce = ");
				for(int i = 0 ; i < nonce_size / 8 ; i++)
					fprintf(output_file, "%02x", nonce[i]);
				fprintf(output_file, "\nPersonalizationString = ");
				for(int i = 0 ; i < per_size / 8 ; i++)
					fprintf(output_file, "%02x", per_string[i]);
				fprintf(output_file, "\nAdditionalInput1 = ");
				for(int i = 0 ; i < add_size / 8 ; i++)
					fprintf(output_file, "%02x", add_input1[i]);
				fprintf(output_file, "\nEntropyInput1 = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy_pr1[i]);
				fprintf(output_file, "\nAdditionalInput2 = ");
				for(int i = 0 ; i < add_size / 8 ; i++)
					fprintf(output_file, "%02x", add_input2[i]);
				fprintf(output_file, "\nEntropyInput2 = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy_pr2[i]);
				fprintf(output_file, "\nReturnedBits = ");
				for(int i = 0 ; i < output_bits / 8 ; i++)
					fprintf(output_file, "%02x", drbg_result[i]);
				fprintf(output_file, "\n\n");
			}
			count = 0;
		}

		fclose(input_file);
		fclose(output_file);
	}

	printf("DRBG test finished \n");
}

void drbg_lsh_testvector_no_pr()
{
	FILE *input_file, *output_file;
	char input_file_name[MAX_FILE_NAME_LEN], output_file_name[MAX_FILE_NAME_LEN];
	lsh_u8 drbg_result[128];

	lsh_u8 read_line[MAX_DATA_LEN];

	lsh_type algtype;
	lsh_u8 entropy[256];
	lsh_u8 entropy_re[256];
	lsh_u8 nonce[256];
	lsh_u8 per_string[256];
	lsh_u8 add_input1[256];
	lsh_u8 add_input_re[256];
	lsh_u8 add_input2[256];

	bool prediction_resistance;
	lsh_uint output_bits;

	lsh_uint reseed_cycle = 1;

	int entropy_size = 0;
	int nonce_size = 0;
	int per_size = 0;
	int add_size = 0;
	int count;

	int r, w;
	lsh_u8 *str_to_int;

	int is, os;
	int is_ary[2] = {256, 512};
	int os_ary[4] = {224, 256, 384, 512};

	for(is = 0, os = 0 ; os < 4 ; os++)
	{
		if(is == 0 && os == 2)
		{
			is = 1;
			os = -1;
			continue;
		}
		sprintf(input_file_name, "DRBG_test/testvector/HASH_DRBG(LSH-%d_%d(-)(no PR))_KAT_req.txt", is_ary[is], os_ary[os]);
		sprintf(output_file_name, "DRBG_test/testvector/HASH_DRBG(LSH-%d_%d(-)(no PR))_KAT_rsp.txt", is_ary[is], os_ary[os]);
		input_file = fopen(input_file_name, "r");
		output_file = fopen(output_file_name, "w");

		if(input_file == NULL)
		{
			printf("file does not exist \n");
			return;
		}
		else
			printf("test data from: %s \n", input_file_name);

		for(int i = 0 ; i < 4 ; i++)
		{
			fgets(read_line, MAX_READ_LEN, input_file);	// read algtype
			read_line[strlen(read_line) - 1] = '\0';

			if(!strcmp(read_line, "[LSH-256_224]"))
			{
				output_bits = 448;
				algtype = LSH_TYPE_256_224;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-256_224\n");
			}
			else if(!strcmp(read_line, "[LSH-256_256]"))
			{
				output_bits = 512;
				algtype = LSH_TYPE_256_256;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-256_256\n");
			}
			else if(!strcmp(read_line, "[LSH-512_224]"))
			{
				output_bits = 448;
				algtype = LSH_TYPE_512_224;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_224\n");
			}
			else if(!strcmp(read_line, "[LSH-512_256]"))
			{
				output_bits = 512;
				algtype = LSH_TYPE_512_256;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_256\n");
			}
			else if(!strcmp(read_line, "[LSH-512_384]"))
			{
				output_bits = 768;
				algtype = LSH_TYPE_512_384;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_384\n");
			}
			else if(!strcmp(read_line, "[LSH-512_512]"))
			{
				output_bits = 1024;
				algtype = LSH_TYPE_512_512;
				fprintf(output_file, "Algo_ID = Hash_DRBG_LSH-512_512\n");
			}
			else
			{
				printf("unknown algorithm type \n");
				return;
			}

			fgets(read_line, MAX_READ_LEN, input_file);	// read PR
			read_line[strlen(read_line) - 1] = '\0';
			if(!strcmp(read_line, "[PredictionResistance = True]"))
			{
				prediction_resistance = true;
				fprintf(output_file, "PredictionResistance = True\n");
				printf("Prediction Resistance: True \n");
			}
			else if(!strcmp(read_line, "[PredictionResistance = False]"))
			{
				prediction_resistance = false;
				fprintf(output_file, "PredictionResistance = False\n");
				printf("Prediction Resistance: false \n");
			}
			else
			{
				printf("unknown prediction resistance setting \n");
				return;
			}

			fgets(read_line, MAX_READ_LEN, input_file);	// read entropy length
			str_to_int = &read_line[19];
			entropy_size = atoi(str_to_int);
			fprintf(output_file, "EntropyInputLen = %d\n", entropy_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// read nonce length
			str_to_int = &read_line[11];
			nonce_size = atoi(str_to_int);
			fprintf(output_file, "NonceLen = %d\n", nonce_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// read persnalization length
			str_to_int = &read_line[27];
			per_size = atoi(str_to_int);
			fprintf(output_file, "PersonalizationStringLen = %d\n", per_size);

			fgets(read_line, MAX_READ_LEN, input_file); // read additional length
			str_to_int = &read_line[21];
			add_size = atoi(str_to_int);
			fprintf(output_file, "AdditionalInputLen = %d\n\n", add_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// skip line

			while(count != 14)
			{
				fgets(read_line, MAX_READ_LEN, input_file);	// get count
				str_to_int = &read_line[8];
				count = atoi(str_to_int);

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy
				for(r = 15, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get nocne
				for(r = 8, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					nonce[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file); // get personalization string
				if(per_size)
				{
					for(r = 24, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						per_string[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get additional input1
				if(add_size)
				{
					for(r = 18, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						add_input1[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy pr1
				for(r = 21, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy_re[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get additional input2
				if(add_size)
				{
					for(r = 24, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						add_input_re[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy pr2
				if(add_size)
				{
					for(r = 18, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						add_input2[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// skip line

				drbg_lsh_testvector_no_pr_digest(algtype, prediction_resistance, entropy, entropy_re, entropy_size, nonce, nonce_size, per_string, per_size, add_input1, add_input_re, add_input2, add_size, output_bits, reseed_cycle, drbg_result);

				fprintf(output_file, "COUNT = %d\n", count);
				fprintf(output_file, "EntropyInput = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy[i]);
				fprintf(output_file, "\nNonce = ");
				for(int i = 0 ; i < nonce_size / 8 ; i++)
					fprintf(output_file, "%02x", nonce[i]);
				fprintf(output_file, "\nPersonalizationString = ");
				for(int i = 0 ; i < per_size / 8 ; i++)
					fprintf(output_file, "%02x", per_string[i]);
				fprintf(output_file, "\nAdditionalInput1 = ");
				for(int i = 0 ; i < add_size / 8 ; i++)
					fprintf(output_file, "%02x", add_input1[i]);
				fprintf(output_file, "\nEntropyInputReseed = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy_re[i]);
				fprintf(output_file, "\nAdditionalInputReseed = ");
				for(int i = 0 ; i < add_size / 8 ; i++)
					fprintf(output_file, "%02x", add_input_re[i]);
				fprintf(output_file, "\nAdditionalInput2 = ");
				for(int i = 0 ; i < add_size / 8 ; i++)
					fprintf(output_file, "%02x", add_input2[i]);
				fprintf(output_file, "\nReturnedBits = ");
				for(int i = 0 ; i < output_bits / 8 ; i++)
					fprintf(output_file, "%02x", drbg_result[i]);
				fprintf(output_file, "\n\n");
			}
			count = 0;
		}

		fclose(input_file);
		fclose(output_file);
	}

	printf("DRBG testvector finished \n");
}

void hmac_drbg_lsh_testvector_pr()
{
	FILE *input_file, *output_file;
	char input_file_name[MAX_FILE_NAME_LEN], output_file_name[MAX_FILE_NAME_LEN];
	lsh_u8 drbg_result[128];

	lsh_u8 read_line[MAX_DATA_LEN];

	lsh_type algtype;
	lsh_u8 entropy[256];
	lsh_u8 entropy_pr1[256];
	lsh_u8 entropy_pr2[256];
	lsh_u8 nonce[256];
	lsh_u8 per_string[256];
	lsh_u8 add_input1[256];
	lsh_u8 add_input2[256];

	bool prediction_resistance;
	lsh_uint output_bits;

	lsh_uint reseed_cycle = 1;

	int entropy_size = 0;
	int nonce_size = 0;
	int per_size = 0;
	int add_size = 0;
	int count;

	int r, w;
	lsh_u8 *str_to_int;

	int is, os;
	int is_ary[2] = {256, 512};
	int os_ary[4] = {224, 256, 384, 512};

	for(is = 0, os = 0 ; os < 4 ; os++)
	{
		if(is == 0 && os == 2)
		{
			is = 1;
			os = -1;
			continue;
		}

		sprintf(input_file_name, "HMAC_DRBG_test/testvector/HMAC_DRBG(LSH-%d_%d(-)(PR))_KAT_req.txt", is_ary[is], os_ary[os]);
		sprintf(output_file_name, "HMAC_DRBG_test/testvector/HMAC_DRBG(LSH-%d_%d(-)(PR))_KAT_rsp.txt", is_ary[is], os_ary[os]);
		input_file = fopen(input_file_name, "r");
		output_file = fopen(output_file_name, "w");

		if(input_file == NULL)
		{
			printf("file does not exist \n");
			return;
		}
		else
			printf("test data from: %s \n", input_file_name);

		for(int i = 0 ; i < 4 ; i++)
		{
			fgets(read_line, MAX_READ_LEN, input_file);	// read algtype
			read_line[strlen(read_line) - 1] = '\0';

			if(!strcmp(read_line, "[LSH-256_224]"))
			{
				output_bits = 448;
				algtype = LSH_TYPE_256_224;
				fprintf(output_file, "Algo_ID = HMAC_DRBG_LSH-256_224\n");
			}
			else if(!strcmp(read_line, "[LSH-256_256]"))
			{
				output_bits = 512;
				algtype = LSH_TYPE_256_256;
				fprintf(output_file, "Algo_ID = HMAC_DRBG_LSH-256_256\n");
			}
			else if(!strcmp(read_line, "[LSH-512_224]"))
			{
				output_bits = 448;
				algtype = LSH_TYPE_512_224;
				fprintf(output_file, "Algo_ID = HMAC_DRBG_LSH-512_224\n");
			}
			else if(!strcmp(read_line, "[LSH-512_256]"))
			{
				output_bits = 512;
				algtype = LSH_TYPE_512_256;
				fprintf(output_file, "Algo_ID = HMAC_DRBG_LSH-512_256\n");
			}
			else if(!strcmp(read_line, "[LSH-512_384]"))
			{
				output_bits = 768;
				algtype = LSH_TYPE_512_384;
				fprintf(output_file, "Algo_ID = HMAC_DRBG_LSH-512_384\n");
			}
			else if(!strcmp(read_line, "[LSH-512_512]"))
			{
				output_bits = 1024;
				algtype = LSH_TYPE_512_512;
				fprintf(output_file, "Algo_ID = HMAC_DRBG_LSH-512_512\n");
			}
			else
			{
				printf("unknown algorithm type \n");
				return;
			}

			fgets(read_line, MAX_READ_LEN, input_file);	// read PR
			read_line[strlen(read_line) - 1] = '\0';
			if(!strcmp(read_line, "[PredictionResistance = True]"))
			{
				prediction_resistance = true;
				fprintf(output_file, "PredictionResistance = True\n");
			}
			else if(!strcmp(read_line, "[PredictionResistance = False]"))
			{
				prediction_resistance = false;
				fprintf(output_file, "PredictionResistance = False\n");
			}
			else
			{
				printf("unknown prediction resistance setting \n");
				return;
			}

			fgets(read_line, MAX_READ_LEN, input_file);	// read entropy length
			str_to_int = &read_line[19];
			entropy_size = atoi(str_to_int);
			fprintf(output_file, "EntropyInputLen = %d\n", entropy_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// read nonce length
			str_to_int = &read_line[11];
			nonce_size = atoi(str_to_int);
			fprintf(output_file, "NonceLen = %d\n", nonce_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// read persnalization length
			str_to_int = &read_line[27];
			per_size = atoi(str_to_int);
			fprintf(output_file, "PersonalizationStringLen = %d\n", per_size);

			fgets(read_line, MAX_READ_LEN, input_file); // read additional length
			str_to_int = &read_line[21];
			add_size = atoi(str_to_int);
			fprintf(output_file, "AdditionalInputLen = %d\n\n", add_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// skip line

			while(count != 14)
			{
				fgets(read_line, MAX_READ_LEN, input_file);	// get count
				str_to_int = &read_line[8];
				count = atoi(str_to_int);

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy
				for(r = 15, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get nocne
				for(r = 8, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					nonce[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file); // get personalization string
				if(per_size)
				{
					for(r = 24, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						per_string[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get additional input1
				if(add_size)
				{
					for(r = 18, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						add_input1[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy pr1
				for(r = 17, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy_pr1[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get additional input2
				if(add_size)
				{
					for(r = 18, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						add_input2[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy pr2
				for(r = 17, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy_pr2[w++] = strtol(str_to_hex, NULL, 16);
				}
				fgets(read_line, MAX_READ_LEN, input_file);	// skip line

				hmac_drbg_lsh_tv_pr_digest(algtype, prediction_resistance, entropy, entropy_pr1, entropy_pr2, entropy_size, nonce, nonce_size, per_string, per_size, add_input1, add_input2, add_size, output_bits, reseed_cycle, drbg_result);

				fprintf(output_file, "COUNT = %d\n", count);
				fprintf(output_file, "EntropyInput = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy[i]);
				fprintf(output_file, "\nNonce = ");
				for(int i = 0 ; i < nonce_size / 8 ; i++)
					fprintf(output_file, "%02x", nonce[i]);
				fprintf(output_file, "\nPersonalizationString = ");
				for(int i = 0 ; i < per_size / 8 ; i++)
					fprintf(output_file, "%02x", per_string[i]);
				fprintf(output_file, "\nAdditionalInput1 = ");
				for(int i = 0 ; i < add_size / 8 ; i++)
					fprintf(output_file, "%02x", add_input1[i]);
				fprintf(output_file, "\nEntropyInput1 = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy_pr1[i]);
				fprintf(output_file, "\nAdditionalInput2 = ");
				for(int i = 0 ; i < add_size / 8 ; i++)
					fprintf(output_file, "%02x", add_input2[i]);
				fprintf(output_file, "\nEntropyInput2 = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy_pr2[i]);
				fprintf(output_file, "\nReturnedBits = ");
				for(int i = 0 ; i < output_bits / 8 ; i++)
					fprintf(output_file, "%02x", drbg_result[i]);
				fprintf(output_file, "\n\n");
			}
			count = 0;
		}

		fclose(input_file);
		fclose(output_file);
	}

	printf("HMAC DRBG testvector finished \n");
}

void hmac_drbg_lsh_testvector_no_pr()
{
	FILE *input_file, *output_file;
	char input_file_name[MAX_FILE_NAME_LEN], output_file_name[MAX_FILE_NAME_LEN];
	lsh_u8 drbg_result[128];

	lsh_u8 read_line[MAX_DATA_LEN];

	lsh_type algtype;
	lsh_u8 entropy[256];
	lsh_u8 entropy_re[256];
	lsh_u8 nonce[256];
	lsh_u8 per_string[256];
	lsh_u8 add_input1[256];
	lsh_u8 add_input_re[256];
	lsh_u8 add_input2[256];

	bool prediction_resistance;
	lsh_uint output_bits;

	lsh_uint reseed_cycle = 1;

	int entropy_size = 0;
	int nonce_size = 0;
	int per_size = 0;
	int add_size = 0;
	int count;

	int r, w;
	lsh_u8 *str_to_int;

	int is, os;
	int is_ary[2] = {256, 512};
	int os_ary[4] = {224, 256, 384, 512};

	for(is = 0, os = 0 ; os < 4 ; os++)
	{
		if(is == 0 && os == 2)
		{
			is = 1;
			os = -1;
			continue;
		}
		sprintf(input_file_name, "HMAC_DRBG_test/testvector/HMAC_DRBG(LSH-%d_%d(-)(no PR))_KAT_req.txt", is_ary[is], os_ary[os]);
		sprintf(output_file_name, "HMAC_DRBG_test/testvector/HMAC_DRBG(LSH-%d_%d(-)(no PR))_KAT_rsp.txt", is_ary[is], os_ary[os]);
		input_file = fopen(input_file_name, "r");
		output_file = fopen(output_file_name, "w");

		if(input_file == NULL)
		{
			printf("file does not exist \n");
			return;
		}
		else
			printf("test data from: %s \n", input_file_name);

		for(int i = 0 ; i < 4 ; i++)
		{
			fgets(read_line, MAX_READ_LEN, input_file);	// read algtype
			read_line[strlen(read_line) - 1] = '\0';

			if(!strcmp(read_line, "[LSH-256_224]"))
			{
				output_bits = 448;
				algtype = LSH_TYPE_256_224;
				fprintf(output_file, "Algo_ID = HMAC_DRBG_LSH-256_224\n");
			}
			else if(!strcmp(read_line, "[LSH-256_256]"))
			{
				output_bits = 512;
				algtype = LSH_TYPE_256_256;
				fprintf(output_file, "Algo_ID = HMAC_DRBG_LSH-256_256\n");
			}
			else if(!strcmp(read_line, "[LSH-512_224]"))
			{
				output_bits = 448;
				algtype = LSH_TYPE_512_224;
				fprintf(output_file, "Algo_ID = HMAC_DRBG_LSH-512_224\n");
			}
			else if(!strcmp(read_line, "[LSH-512_256]"))
			{
				output_bits = 512;
				algtype = LSH_TYPE_512_256;
				fprintf(output_file, "Algo_ID = HMAC_DRBG_LSH-512_256\n");
			}
			else if(!strcmp(read_line, "[LSH-512_384]"))
			{
				output_bits = 768;
				algtype = LSH_TYPE_512_384;
				fprintf(output_file, "Algo_ID = HMAC_DRBG_LSH-512_384\n");
			}
			else if(!strcmp(read_line, "[LSH-512_512]"))
			{
				output_bits = 1024;
				algtype = LSH_TYPE_512_512;
				fprintf(output_file, "Algo_ID = HMAC_DRBG_LSH-512_512\n");
			}
			else
			{
				printf("unknown algorithm type \n");
				return;
			}

			fgets(read_line, MAX_READ_LEN, input_file);	// read PR
			read_line[strlen(read_line) - 1] = '\0';
			if(!strcmp(read_line, "[PredictionResistance = True]"))
			{
				prediction_resistance = true;
				fprintf(output_file, "PredictionResistance = True\n");
			}
			else if(!strcmp(read_line, "[PredictionResistance = False]"))
			{
				prediction_resistance = false;
				fprintf(output_file, "PredictionResistance = False\n");
			}
			else
			{
				printf("unknown prediction resistance setting \n");
				return;
			}

			fgets(read_line, MAX_READ_LEN, input_file);	// read entropy length
			str_to_int = &read_line[19];
			entropy_size = atoi(str_to_int);
			fprintf(output_file, "EntropyInputLen = %d\n", entropy_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// read nonce length
			str_to_int = &read_line[11];
			nonce_size = atoi(str_to_int);
			fprintf(output_file, "NonceLen = %d\n", nonce_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// read persnalization length
			str_to_int = &read_line[27];
			per_size = atoi(str_to_int);
			fprintf(output_file, "PersonalizationStringLen = %d\n", per_size);

			fgets(read_line, MAX_READ_LEN, input_file); // read additional length
			str_to_int = &read_line[21];
			add_size = atoi(str_to_int);
			fprintf(output_file, "AdditionalInputLen = %d\n\n", add_size);

			fgets(read_line, MAX_READ_LEN, input_file);	// skip line

			while(count != 14)
			{
				fgets(read_line, MAX_READ_LEN, input_file);	// get count
				str_to_int = &read_line[8];
				count = atoi(str_to_int);

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy
				for(r = 15, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get nocne
				for(r = 8, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					nonce[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file); // get personalization string
				if(per_size)
				{
					for(r = 24, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						per_string[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get additional input1
				if(add_size)
				{
					for(r = 18, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						add_input1[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy pr1
				for(r = 21, w = 0 ; r < strlen(read_line) ; r += 2)
				{
					lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
					entropy_re[w++] = strtol(str_to_hex, NULL, 16);
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get additional input2
				if(add_size)
				{
					for(r = 24, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						add_input_re[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// get entropy pr2
				if(add_size)
				{
					for(r = 18, w = 0 ; r < strlen(read_line) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[r], read_line[r+1], '\0'};
						add_input2[w++] = strtol(str_to_hex, NULL, 16);
					}
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// skip line

				hmac_drbg_lsh_tv_no_pr_digest(algtype, prediction_resistance, entropy, entropy_re, entropy_size, nonce, nonce_size, per_string, per_size, add_input1, add_input_re, add_input2, add_size, output_bits, reseed_cycle, drbg_result);

				fprintf(output_file, "COUNT = %d\n", count);
				fprintf(output_file, "EntropyInput = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy[i]);
				fprintf(output_file, "\nNonce = ");
				for(int i = 0 ; i < nonce_size / 8 ; i++)
					fprintf(output_file, "%02x", nonce[i]);
				fprintf(output_file, "\nPersonalizationString = ");
				for(int i = 0 ; i < per_size / 8 ; i++)
					fprintf(output_file, "%02x", per_string[i]);
				fprintf(output_file, "\nAdditionalInput1 = ");
				for(int i = 0 ; i < add_size / 8 ; i++)
					fprintf(output_file, "%02x", add_input1[i]);
				fprintf(output_file, "\nEntropyInputReseed = ");
				for(int i = 0 ; i < entropy_size / 8 ; i++)
					fprintf(output_file, "%02x", entropy_re[i]);
				fprintf(output_file, "\nAdditionalInputReseed = ");
				for(int i = 0 ; i < add_size / 8 ; i++)
					fprintf(output_file, "%02x", add_input_re[i]);
				fprintf(output_file, "\nAdditionalInput2 = ");
				for(int i = 0 ; i < add_size / 8 ; i++)
					fprintf(output_file, "%02x", add_input2[i]);
				fprintf(output_file, "\nReturnedBits = ");
				for(int i = 0 ; i < output_bits / 8 ; i++)
					fprintf(output_file, "%02x", drbg_result[i]);
				fprintf(output_file, "\n\n");
			}
			count = 0;
		}

		fclose(input_file);
		fclose(output_file);
	}

	printf("HMAC DRBG testvector finished \n");
}

int main()
{
	drbg_lsh_test_drive();
	//hmac_drbg_lsh_test_drive();
	//drbg_lsh_testvector_pr();
	//drbg_lsh_testvector_no_pr();
	//hmac_drbg_lsh_testvector_pr();
	//hmac_drbg_lsh_testvector_no_pr();

	return 0;
}
