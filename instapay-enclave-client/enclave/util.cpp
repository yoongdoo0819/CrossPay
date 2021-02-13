#include <util.h>


unsigned char* copy_bytes(unsigned char *data, int n)
{
    unsigned char *output = new unsigned char[n];
    
    memcpy(output, data, n);
    
    return output;
}


std::vector<unsigned char> int_to_bytes(unsigned int i)
{
    std::vector<unsigned char> output;
    unsigned int size, temp;

    for(size = 0, temp = i; temp != 0; size++)
        temp = temp >> 8;

    output.resize(size);

    std::memcpy(output.data(), &i, size);
    std::reverse(output.begin(), output.end());

    return output;
}


unsigned int char_to_int(unsigned char data)
{
    if (data >= '0' && data <= '9')
        return data - '0';
    else if (data >= 'A' && data <= 'F')
        return data - 'A' + 10;
    else if (data >= 'a' && data <= 'f')
        return data - 'a' + 10;
}


unsigned char* arr_to_bytes(unsigned char *data, unsigned int size)
{
    unsigned char ch;
    unsigned char* output = new unsigned char[size / 2];

    for (int i = 0, j = 0; i < size; i += 2, j++) {
        ch = char_to_int(data[i]) * 16 + char_to_int(data[i + 1]);
        output[j] = ch;
    }

    return output;
}


unsigned char* create_uint256_argument(unsigned int a)
{
    unsigned char a_buf[65];
    unsigned char* output;

    snprintf((char *)a_buf, 65, "%064x", a);
    output = ::arr_to_bytes(a_buf, 64);

    return output;
}
