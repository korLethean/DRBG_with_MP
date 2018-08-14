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

	int entropy_size;
	int nonce_size;
	int per_size;
	int add_size;
	int count;

	int r, w;
	lsh_u8 *str_to_int;

	unsigned char *std_name[6] = {"LSH-256_224", "LSH-256_256", "LSH-512_224", "LSH-512_256", "LSH-512_384", "LSH-512_512"};

	int num = 0;

	omp_set_num_threads(MAX_LOOP_COUNT);
#pragma omp parallel for private(input_file_name, output_file_name, input_file, output_file, count, num, algtype, output_bits, entropy, entropy_pr1, entropy_pr2, entropy_size, nonce, nonce_size, add_input1, add_input2, add_size, per_string, per_size, drbg_result, r, w, str_to_int, read_line)
	for(int index = 0 ; index < MAX_LOOP_COUNT ; index++)
	{
		num = 0;
		sprintf(input_file_name, "DRBG_testvector_pr/HASH_DRBG(%s(-)(PR)).txt", std_name[index]);
		sprintf(output_file_name, "DRBG_testvector_pr/HASH_DRBG(%s(-)(PR))_rsp.txt", std_name[index]);

		input_file = fopen(input_file_name, "r");
		output_file = fopen(output_file_name, "w");

		if(input_file != NULL)
		{
			printf("test data from: %s \n", input_file_name);

			while(!feof(input_file))
			{
				fgets(read_line, MAX_READ_LEN, input_file);	// read algtype
				read_line[strlen(read_line) - 1] = '\0';

				if(!strcmp(read_line, "[LSH-256_224]"))
				{
					output_bits = 448;
					algtype = LSH_TYPE_256_224;
				}
				else if(!strcmp(read_line, "[LSH-256_256]"))
				{
					output_bits = 512;
					algtype = LSH_TYPE_256_256;
				}
				else if(!strcmp(read_line, "[LSH-512_224]"))
				{
					output_bits = 448;
					algtype = LSH_TYPE_512_224;
				}
				else if(!strcmp(read_line, "[LSH-512_256]"))
				{
					output_bits = 512;
					algtype = LSH_TYPE_512_256;
				}
				else if(!strcmp(read_line, "[LSH-512_384]"))
				{
					output_bits = 768;
					algtype = LSH_TYPE_512_384;
				}
				else if(!strcmp(read_line, "[LSH-512_512]"))
				{
					output_bits = 1024;
					algtype = LSH_TYPE_512_512;
				}
				else
				{
					printf("%s is unknown algorithm type \n", read_line);
					goto forced_exit;
				}

				fgets(read_line, MAX_READ_LEN, input_file);	// skip line
				prediction_resistance = true;

				fgets(read_line, MAX_READ_LEN, input_file);	// read entropy length
				str_to_int = &read_line[19];
				entropy_size = atoi(str_to_int);

				fgets(read_line, MAX_READ_LEN, input_file);	// read nonce length
				str_to_int = &read_line[11];
				nonce_size = atoi(str_to_int);

				fgets(read_line, MAX_READ_LEN, input_file);	// read persnalization length
				str_to_int = &read_line[27];
				per_size = atoi(str_to_int);

				fgets(read_line, MAX_READ_LEN, input_file); // read additional length
				str_to_int = &read_line[21];
				add_size = atoi(str_to_int);

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

					fprintf(output_file, "output %d = ", num++);
					for(int i = 0 ; i < output_bits / 8 ; i++)
						fprintf(output_file, "%02x", drbg_result[i]);
					fprintf(output_file, "\n\n");

				}
				count = 0;
			}
		}
		else
			printf("file does not exist \n");
	forced_exit:
		fclose(input_file);
		fclose(output_file);
	}

	printf("DRBG test finished \n");
}

int main()
{
	time_t start_time = 0, end_time = 0;
	double excute_time;
	double total_time = 0;
	int loop_count = 2000;

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
