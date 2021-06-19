#ifndef UTIL_H
#define UTIL_H

//#include <vector>
#include <stdio.h>

//using namespace std;

unsigned char* copy_bytes(unsigned char*, int);             // simply copy bytes and return unsigned char array
//std::vector<unsigned char> int_to_bytes(unsigned int);      // convert integer to bytes array
unsigned int char_to_int(unsigned char);                    // convert char to integer
unsigned char* arr_to_bytes(unsigned char*, unsigned int);  // convert unsigned char arry to bytes array
unsigned char* create_uint256_argument(unsigned int);       // create a uint256 argument to call contract function

#endif
