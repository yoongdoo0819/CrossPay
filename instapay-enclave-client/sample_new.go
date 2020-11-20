package main

/*
#cgo CPPFLAGS: -I/home/xiaofo/sgxsdk/include -I./untrusted -I./include
#cgo LDFLAGS: -L. -ltee

#include "untrusted/app.h"
*/
import "C"

func main() {
	C.initialize_enclave()
	cf := C.CString("745a8d1610D4AC940350221F569338E4C93b1De6")
	C.ecall_load_contract_address_w(cf)
}
