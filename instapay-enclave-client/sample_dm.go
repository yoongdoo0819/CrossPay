package main

/*
#cgo CPPFLAGS: -I/home/xiaofo/sgxsdk/include -I./untrusted -I./include
#cgo LDFLAGS: -L. -ltee

#include "untrusted/app.h"
*/
import "C"

import (
	//"fmt"
	// "log"
	// "strconv"
	//"unsafe"
	//"reflect"
	// "context"
	// "github.com/ethereum/go-ethereum/common"
	// "github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	C.initialize_enclave()

	// C.ecall_load_account_data_w()
	// C.ecall_load_channel_data_w()

	/*
	get channel information
	*/
	// var ci unsafe.Pointer
	// ci = C.ecall_get_channel_info_w(C.uint(8))
	// cvtd := (*C.channel)(unsafe.Pointer(ci))

	// fmt.Println(cvtd.m_id)

	// var sig *C.uchar = &(cvtd.m_my_addr[0])
	// hdr := reflect.SliceHeader{
	// 	Data: uintptr(unsafe.Pointer(sig)),
	// 	Len:  int(20),
	// 	Cap:  int(20),
	// }

	// s := *(*[]C.uchar)(unsafe.Pointer(&hdr))
	// for i := 0; i < 20; i++ {
	// 	fmt.Printf("%02x", s[i])
	// }
	// fmt.Println()


	/*
	direct payment  ( Alice ----> Bob )
	*/

	// var originalMsg *C.uchar
	// var signature *C.uchar

	// C.ecall_pay_w(8, 10, &originalMsg, &signature)   // Alice calls it
	// hdr9 := reflect.SliceHeader{
	// 	Data: uintptr(unsafe.Pointer(originalMsg)),
	// 	Len:  int(44),
	// 	Cap:  int(44),
	// }
	// s9 := *(*[]C.uchar)(unsafe.Pointer(&hdr9))
	// for i := C.uint(0); i < 44; i++ {
	// 	fmt.Printf("%02x", s9[i])
	// }

	// var originalMsgByte [44]byte
	// for i := C.uint(0); i < 44; i++ {
	// 	originalMsgByte[i] = byte(s9[i])
	// }
	// fmt.Println()
	// for i := 0; i < 44; i++ {
	// 	fmt.Printf("%02x", originalMsgByte[i])
	// }

	// fmt.Println()
	// data := (*C.uchar)(uintptr(unsafe.Pointer(&originalMsgByte[0])) + uintptr(44))
	
	// fmt.Printf("%02x", data)

	// var replyMsg *C.uchar
	// var replySig *C.uchar
	// C.ecall_paid_w(originalMsg, signature, &replyMsg, &replySig)	// Bob calls it
	// fmt.Println()

	/* sign and verify */
	C.ecall_test_func_w()
}
