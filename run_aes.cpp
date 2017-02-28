#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "aes.h"

// Declare file handlers
static FILE *key_file, *input_file, *output_file;

// Declare action parameters
#define ACTION_GENERATE_KEY "-g"
#define ACTION_ENCRYPT "-e"
#define ACTION_DECRYPT "-d"

// AES key is 16 bytes long
#define AES_KEY_SIZE 16

#define malloc16Bytes (uint8_t*) malloc(16 * sizeof(uint8_t))

bool encryption_mode = true;

int main(int argc, char* argv[]) {
	clock_t start, finish;
	double time_taken;
	unsigned long file_size;
	unsigned short int padding;
	int nThread = 2;

	if (argc < 2) {
		printf("You must provide at least 1 parameter, where you specify the action.");
		return 1;
	}

	if (strcmp(argv[1], ACTION_GENERATE_KEY) == 0) { // Generate key file
		// if (argc != 3) {
		// 	printf("Invalid # of parameter specified. Usage: run_aes -g keyfile.key");
		// 	return 1;
		// }
		//
		// key_file = fopen(argv[2], "wb");
		// if (!key_file) {
		// 	printf("Could not open file to write key.");
		// 	return 1;
		// }
		//
		// unsigned int iseed = (unsigned int)time(NULL);
		// srand (iseed);
		//
		// short int bytes_written;
		// fclose(key_file);
	} else if ((strcmp(argv[1], ACTION_ENCRYPT) == 0) || (strcmp(argv[1], ACTION_DECRYPT) == 0)) { // Encrypt or decrypt
		if (argc != 5) {
			printf("Invalid # of parameters (%d) specified. Usage: run_des [-e|-d] keyfile.key input.file output.file", argc);
			return 1;
		}

		// Read key file
		key_file = fopen(argv[2], "rb");
		if (!key_file) {
			printf("Could not open key file to read key.");
			return 1;
		}

		short int bytes_read;
		uint8_t *aes_key = malloc16Bytes;
		bytes_read = fread(aes_key, sizeof(uint8_t), AES_KEY_SIZE, key_file);
		if (bytes_read != AES_KEY_SIZE) {
			printf("Key read from key file does nto have valid key size.");
			fclose(key_file);
			return 1;
		}
		fclose(key_file);

		// Open input file
		input_file = fopen(argv[3], "rb");
		if (!input_file) {
			printf("Could not open input file to read data.");
			return 1;
		}

		// Open output file
		output_file = fopen(argv[4], "wb");
		if (!output_file) {
			printf("Could not open output file to write data.");
			return 1;
		}

		// Generate DES key set
		short int bytes_written, process_mode;
		unsigned long block_count = 0, number_of_blocks;
		uint8_t* data_block = malloc16Bytes;
		uint8_t* processed_block = malloc16Bytes;
		// key_set* key_sets = (key_set*)malloc(17*sizeof(key_set));

		// Determine process mode
		if (strcmp(argv[1], ACTION_ENCRYPT) == 0) {
			// process_mode = ENCRYPTION_MODE;
			encryption_mode = true;
			printf("Encrypting..\n");
		} else {
			encryption_mode = false;
			// process_mode = DECRYPTION_MODE;
			printf("Decrypting..\n");
		}

		// Get number of blocks in the file
		fseek(input_file, 0L, SEEK_END);
		file_size = ftell(input_file);

		fseek(input_file, 0L, SEEK_SET);
		// 16 bytes * 8 bits / bytes = 128 bits
		number_of_blocks = file_size/16 + ((file_size%16)?1:0);

		start = clock();

		// Start reading input file, process and write to output file
		while (fread(data_block, 1, 16, input_file)) {
      block_count++;
			if (block_count == number_of_blocks) {
				padding = 16 - file_size%16;
				if (padding < 16) {
					memset((data_block + 16 - padding), (uint8_t)padding, padding);
				}
			}
			if (encryption_mode) {
				AES128_ECB_encrypt(data_block, aes_key, processed_block);
			} else { // Decrypt
				AES128_ECB_decrypt(data_block, aes_key, processed_block);
			}
      bytes_written = fwrite(processed_block, 1, 16, output_file);
      memset(data_block, 0, 16);
		}

		finish = clock();

		// Free up memory
		free(aes_key);
		free(data_block);
		free(processed_block);
		fclose(input_file);
		fclose(output_file);

		// Provide feedback
		time_taken = (double)(finish - start)/(double)CLOCKS_PER_SEC;
		printf("Finished processing %s. Time taken: %lf seconds.\n", argv[3], time_taken);
		return 0;
	} else {
		printf("Invalid action: %s. First parameter must be [ -g | -e | -d ].", argv[1]);
		return 1;
	}

	return 0;
}
