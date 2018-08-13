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
#include <time.h>
#include <omp.h>
#include "include/drbg.h"
#include "include/hmac_drbg.h"

#define MAX_FILE_NAME_LEN 256
#define MAX_READ_LEN 1024
#define MAX_DATA_LEN 1024	// original 256 * 4

#pragma warning(disable: 4996)

void drbg_lsh_testvector_pr()
{
	const int MAX_LOOP_COUNT = 6;

	FILE *input_file[MAX_LOOP_COUNT], *output_file[MAX_LOOP_COUNT];
	char input_file_name[MAX_FILE_NAME_LEN], output_file_name[MAX_FILE_NAME_LEN];
	lsh_u8 drbg_result[MAX_LOOP_COUNT][128];

	lsh_u8 read_line[MAX_LOOP_COUNT][MAX_DATA_LEN];

	lsh_type algtype;
	lsh_u8 entropy[MAX_LOOP_COUNT][256];
	lsh_u8 entropy_pr1[MAX_LOOP_COUNT][256];
	lsh_u8 entropy_pr2[MAX_LOOP_COUNT][256];
	lsh_u8 nonce[MAX_LOOP_COUNT][256];
	lsh_u8 per_string[MAX_LOOP_COUNT][256];
	lsh_u8 add_input1[MAX_LOOP_COUNT][256];
	lsh_u8 add_input2[MAX_LOOP_COUNT][256];

	bool prediction_resistance;
	lsh_uint output_bits;

	lsh_uint reseed_cycle = 1;

	int entropy_size;
	int nonce_size;
	int per_size;
	int add_size;
	int count;

	int r, w;
	lsh_u8 *str_to_int[MAX_LOOP_COUNT];

	unsigned char *std_name[6] = {"LSH-256_224", "LSH-256_256", "LSH-512_224", "LSH-512_256", "LSH-512_384", "LSH-512_512"};

	int num = 0;

#pragma omp parallel for private(input_file_name, output_file_name, count, num, algtype, output_bits, entropy_size, nonce_size, add_size, per_size)
	for(int index = 0 ; index < MAX_LOOP_COUNT ; index++)
	{
		num = 0;
		sprintf(input_file_name, "DRBG_testvector_pr/HASH_DRBG(%s(-)(PR)).txt", std_name[index]);
		sprintf(output_file_name, "DRBG_testvector_pr/HASH_DRBG(%s(-)(PR))_rsp.txt", std_name[index]);

		input_file[index] = fopen(input_file_name, "r");
		output_file[index] = fopen(output_file_name, "w");

		if(input_file[index] != NULL)
		{
			printf("test data from: %s \n", input_file_name);

			while(!feof(input_file[index]))
			{
				fgets(read_line[index], MAX_READ_LEN, input_file[index]);	// read algtype
				read_line[index][strlen(read_line[index]) - 1] = '\0';

				if(!strcmp(read_line[index], "[LSH-256_224]"))
				{
					output_bits = 448;
					algtype = LSH_TYPE_256_224;
				}
				else if(!strcmp(read_line[index], "[LSH-256_256]"))
				{
					output_bits = 512;
					algtype = LSH_TYPE_256_256;
				}
				else if(!strcmp(read_line[index], "[LSH-512_224]"))
				{
					output_bits = 448;
					algtype = LSH_TYPE_512_224;
				}
				else if(!strcmp(read_line[index], "[LSH-512_256]"))
				{
					output_bits = 512;
					algtype = LSH_TYPE_512_256;
				}
				else if(!strcmp(read_line[index], "[LSH-512_384]"))
				{
					output_bits = 768;
					algtype = LSH_TYPE_512_384;
				}
				else if(!strcmp(read_line[index], "[LSH-512_512]"))
				{
					output_bits = 1024;
					algtype = LSH_TYPE_512_512;
				}
				else
				{
					printf("%s is unknown algorithm type \n", read_line[index]);
					goto forced_exit;
				}

				fgets(read_line[index], MAX_READ_LEN, input_file[index]);	// skip line
				prediction_resistance = true;

				fgets(read_line[index], MAX_READ_LEN, input_file[index]);	// read entropy length
				str_to_int[index] = &read_line[index][19];
				entropy_size = atoi(str_to_int[index]);

				fgets(read_line[index], MAX_READ_LEN, input_file[index]);	// read nonce length
				str_to_int[index] = &read_line[index][11];
				nonce_size = atoi(str_to_int[index]);

				fgets(read_line[index], MAX_READ_LEN, input_file[index]);	// read persnalization length
				str_to_int[index] = &read_line[index][27];
				per_size = atoi(str_to_int[index]);

				fgets(read_line[index], MAX_READ_LEN, input_file[index]); // read additional length
				str_to_int[index] = &read_line[index][21];
				add_size = atoi(str_to_int[index]);

				fgets(read_line[index], MAX_READ_LEN, input_file[index]);	// skip line

				while(count != 14)
				{
					fgets(read_line[index], MAX_READ_LEN, input_file[index]);	// get count
					str_to_int[index] = &read_line[index][8];
					count = atoi(str_to_int[index]);

					fgets(read_line[index], MAX_READ_LEN, input_file[index]);	// get entropy
					for(r = 15, w = 0 ; r < strlen(read_line[index]) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[index][r], read_line[index][r+1], '\0'};
						entropy[index][w++] = strtol(str_to_hex, NULL, 16);
					}

					fgets(read_line[index], MAX_READ_LEN, input_file[index]);	// get nocne
					for(r = 8, w = 0 ; r < strlen(read_line[index]) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[index][r], read_line[index][r+1], '\0'};
						nonce[index][w++] = strtol(str_to_hex, NULL, 16);
					}

					fgets(read_line[index], MAX_READ_LEN, input_file[index]); // get personalization string
					if(per_size)
					{
						for(r = 24, w = 0 ; r < strlen(read_line[index]) ; r += 2)
						{
							lsh_u8 str_to_hex[3] = {read_line[index][r], read_line[index][r+1], '\0'};
							per_string[index][w++] = strtol(str_to_hex, NULL, 16);
						}
					}

					fgets(read_line[index], MAX_READ_LEN, input_file[index]);	// get additional input1
					if(add_size)
					{
						for(r = 18, w = 0 ; r < strlen(read_line[index]) ; r += 2)
						{
							lsh_u8 str_to_hex[3] = {read_line[index][r], read_line[index][r+1], '\0'};
							add_input1[index][w++] = strtol(str_to_hex, NULL, 16);
						}
					}

					fgets(read_line[index], MAX_READ_LEN, input_file[index]);	// get entropy pr1
					for(r = 17, w = 0 ; r < strlen(read_line[index]) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[index][r], read_line[index][r+1], '\0'};
						entropy_pr1[index][w++] = strtol(str_to_hex, NULL, 16);
					}

					fgets(read_line[index], MAX_READ_LEN, input_file[index]);	// get additional input2
					if(add_size)
					{
						for(r = 18, w = 0 ; r < strlen(read_line[index]) ; r += 2)
						{
							lsh_u8 str_to_hex[3] = {read_line[index][r], read_line[index][r+1], '\0'};
							add_input2[index][w++] = strtol(str_to_hex, NULL, 16);
						}
					}

					fgets(read_line[index], MAX_READ_LEN, input_file[index]);	// get entropy pr2
					for(r = 17, w = 0 ; r < strlen(read_line[index]) ; r += 2)
					{
						lsh_u8 str_to_hex[3] = {read_line[index][r], read_line[index][r+1], '\0'};
						entropy_pr2[index][w++] = strtol(str_to_hex, NULL, 16);
					}
					fgets(read_line[index], MAX_READ_LEN, input_file[index]);	// skip line

					/// 여기 작업해야함 ///
					drbg_lsh_testvector_pr_digest(algtype, prediction_resistance, entropy[index], entropy_pr1[index], entropy_pr2[index], entropy_size, nonce[index], nonce_size, per_string[index], per_size, add_input1[index], add_input2[index], add_size, output_bits, reseed_cycle, drbg_result[index]);

					fprintf(output_file[index], "output %d = ", num++);
					for(int i = 0 ; i < output_bits / 8 ; i++)
						fprintf(output_file[index], "%02x", drbg_result[index][i]);
					fprintf(output_file[index], "\n\n");
				}
				count = 0;
			}
		}
		else
			printf("file does not exist \n");
	forced_exit:
		fclose(input_file[index]);
		fclose(output_file[index]);
	}

	printf("DRBG test finished \n");
}

int main()
{
	time_t start_time = 0, end_time = 0;
	double excute_time;
	double total_time = 0;
	int loop_count = 1;

	for(int i = 0 ; i < loop_count ; i++)
	{
		start_time = clock();

		drbg_lsh_testvector_pr();

		end_time = clock();
		excute_time = (double)(end_time - start_time);
		total_time += excute_time;

		printf("Time spent: %.f milliseconds \n", excute_time);
	}
	printf("Total Time spend: %.f milliseconds \n", total_time);
	printf("Average Time spent of %d loops: %.f milliseconds \n", loop_count, total_time / loop_count);

	return 0;
}
