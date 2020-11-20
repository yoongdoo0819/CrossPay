package main

/*
#cgo CPPFLAGS: -I/home/xiaofo/sgxsdk/include -I./untrusted -I./include
#cgo LDFLAGS: -L. -ltee

#include "untrusted/app.h"
*/
import "C"

import (
	// "log"
	// "strconv"
	"unsafe"
	"reflect"
	"fmt"
	// "context"
	// "github.com/ethereum/go-ethereum/common"
	// "github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	C.initialize_enclave()

	/*
	direct payment  ( Alice ----> Bob )
	// */
	
	kf := C.CString("data/key/k0")
	cf := C.CString("data/channel/c0")
	defer C.free(unsafe.Pointer(kf))
	defer C.free(unsafe.Pointer(cf))
	C.ecall_load_account_data_w(kf)
	C.ecall_load_channel_data_w(cf)

	var originalMsg *C.uchar
	var signature *C.uchar

	C.ecall_pay_w(8, 8, &originalMsg, &signature)

	byteArray, sigByteArray := convertPointerToByte(originalMsg, signature)

	fmt.Printf("%02x", byteArray)
	fmt.Println()
	fmt.Printf("%02x", sigByteArray)

	originalPointer, sigPointer := convertByteToPointer(byteArray, sigByteArray)

	hdr1 := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(originalPointer)),
		Len: int(44),
		Cap: int(44),
	}
	s1 := *(*[]C.uchar)(unsafe.Pointer(&hdr1))

	hdr2 := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(sigPointer)),
		Len: int(65),
		Cap: int(65),
	}
	s2 := *(*[]C.uchar)(unsafe.Pointer(&hdr2))
	fmt.Println()
	for i := C.uint(0); i < 44; i++ {
		fmt.Printf("%02x", s1[i])
	}
	fmt.Println()
	for i := C.uint(0); i < 65; i++ {
		fmt.Printf("%02x", s2[i])
	}
}

func convertByteToPointer(originalMsg []byte, signature []byte) (*C.uchar, *C.uchar){

	var uOriginal [44]C.uchar
	var uSignature [65]C.uchar

	for i := 0; i < 44; i++{
		uOriginal[i] = C.uchar(originalMsg[i])
	}

	for i := 0; i < 65; i++{
		uSignature[i] = C.uchar(signature[i])
	}

	cOriginalMsg := (*C.uchar)(unsafe.Pointer(&uOriginal[0]))
	cSignature := (*C.uchar)(unsafe.Pointer(&uSignature[0]))

	return cOriginalMsg, cSignature
}

func convertPointerToByte(originalMsg *C.uchar, signature *C.uchar)([]byte, []byte){

	var returnMsg []byte
	var returnSignature []byte

	replyMsgHdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(originalMsg)),
		Len: int(44),
		Cap: int(44),
	}
	replyMsgS := *(*[]C.uchar)(unsafe.Pointer(&replyMsgHdr))

	replySigHdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(signature)),
		Len: int(65),
		Cap: int(65),
	}
	replySigS := *(*[]C.uchar)(unsafe.Pointer(&replySigHdr))

	for i := 0; i < 44; i++{
		returnMsg = append(returnMsg, byte(replyMsgS[i]))
	}

	for i := 0; i < 65; i++{
		returnSignature = append(returnSignature, byte(replySigS[i]))
	}

	return returnMsg, returnSignature
}