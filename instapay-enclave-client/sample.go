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
	//"unsafe"
	//"reflect"
	// "context"
	// "github.com/ethereum/go-ethereum/common"
	// "github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	C.initialize_enclave()


	// /* calling ecall_preset_account_w */
	// owner := []C.uchar("D03A2CC08755eC7D75887f0997195654b928893e")
	// key := []C.uchar("e113ff405699b7779fbe278ee237f2988b1e6769d586d8803860d49f28359fbd")
	// C.ecall_preset_account_w(&owner[0], &key[0])


	/* calling ecall_onchain_payment */
	// if err != nil{
	// 	log.Println(err)
	// }
	// client, err := ethclient.Dial("ws://141.223.121.164:8881")
	// if err != nil{
	// 	log.Fatal(err)
	// }
	// address := common.HexToAddress("0xD03A2CC08755eC7D75887f0997195654b928893e")
	// nonce, err := client.PendingNonceAt(context.Background(), address)
	// convertedNonce := C.uint(nonce)
	// owner := []C.uchar("D03A2CC08755eC7D75887f0997195654b928893e")
	// receiver := []C.uchar("0b4161ad4f49781a821c308d672e6c669139843c")
	// amount := C.uint(8)
	// SigLen := C.uint(0)

	// var sig *C.uchar = C.ecall_onchain_payment_w(convertedNonce, &owner[0], &receiver[0], amount, &SigLen)
	// hdr := reflect.SliceHeader{
	// 	Data: uintptr(unsafe.Pointer(sig)),
	// 	Len:  int(SigLen),
	// 	Cap:  int(SigLen),
	// }

	// fmt.Println("트랜잭션 서명 값.")

	// s := *(*[]C.uchar)(unsafe.Pointer(&hdr))
	// var convertedStr string
	// convertedStr = fmt.Sprintf("%02x", s)
	// for i := C.uint(0); i < SigLen; i++ {
    //     fmt.Printf("%02x", s[i])
	// }
	// fmt.Println("트랜잭션 서명 값222.")
	// fmt.Println(convertedStr)


	/* calling ecall_create_channel_w */
	
	// client, err := ethclient.Dial("ws://141.223.121.164:8881")
	// if err != nil{
	// 	log.Println(err)
	// }
	// address := common.HexToAddress("0xD03A2CC08755eC7D75887f0997195654b928893e")
	// nonce, err := client.PendingNonceAt(context.Background(), address)
	// convertedNonce := C.uint(nonce)
	// owner := []C.uchar("D03A2CC08755eC7D75887f0997195654b928893e")
	// receiver := []C.uchar("0b4161ad4f49781a821c308d672e6c669139843c")
	// deposit := C.uint(800)
	// SigLen := C.uint(0)

	// var sig1 *C.uchar = C.ecall_create_channel_w(convertedNonce, &owner[0], &receiver[0], deposit, &SigLen)
	// hdr1 := reflect.SliceHeader{
	// 	Data: uintptr(unsafe.Pointer(sig1)),
	// 	Len:  int(SigLen),
	// 	Cap:  int(SigLen),
	// }
	// s := *(*[]C.uchar)(unsafe.Pointer(&hdr1))
	// for i := C.uint(0); i < SigLen; i++ {
    //     fmt.Printf("%02x", s[i])
	// }

	// s1 := *(*[]C.uchar)(unsafe.Pointer(&hdr1))
	// for i := C.uint(0); i < SigLen; i++ {
    //     fmt.Printf("%02x", s1[i])
	// }
	// fmt.Println()


	// /* calling ecall_create_account_w */
	// var sig1 *C.uchar = C.ecall_create_account_w()
	// hdr1 := reflect.SliceHeader{
	// 	Data: uintptr(unsafe.Pointer(sig1)),
	// 	Len:  20,
	// 	Cap:  20,
	// }

	// s1 := *(*[]C.uchar)(unsafe.Pointer(&hdr1))
	// for i := C.uint(0); i < 20; i++ {
    //     fmt.Printf("%02x", s1[i])
	// }
	// fmt.Println()


	// /* calling ecall_receive_create_channel_w */
    // /*
    //                  id: 2                   id: 3
    //     A(0x7890...) -----> owner(0xd03a...) -----> B(0x0b41...)
    // */	
	// channel_id := C.uint(2)
	// A := []C.uchar("78902c58006916201F65f52f7834e467877f0500")
	// B := []C.uchar("0b4161ad4f49781a821c308d672e6c669139843c")
	// deposit = C.uint(5)
	// C.ecall_receive_create_channel_w(channel_id, &A[0], &owner[0], deposit)

	// channel_id = C.uint(3)
	// deposit = C.uint(9)
	// C.ecall_receive_create_channel_w(channel_id, &owner[0], &B[0], deposit)


	// fmt.Printf("[BEFORE] CHANNEL 2 BALANCE: %d\n", C.ecall_get_balance_w(C.uint(2)))
	// fmt.Printf("[BEFORE] CHANNEL 3 BALANCE: %d\n", C.ecall_get_balance_w(C.uint(3)))
	// fmt.Println()


	// /*
	// 	calling ecall_go_pre_update_w
	// 	received agreement request
	// */
	// payment_num := C.uint(30)
	// channel_ids := []C.uint{2, 3}
	// amount := []C.int{4, -4}
	// size := C.uint(2)
	// C.ecall_go_pre_update_w(payment_num, &channel_ids[0], &amount[0], size);

	// fmt.Printf("[PRE-UPDATE] CHANNEL 2 BALANCE: %d\n", C.ecall_get_balance_w(C.uint(2)))
	// fmt.Printf("[PRE-UPDATE] CHANNEL 3 BALANCE: %d\n", C.ecall_get_balance_w(C.uint(3)))
	// fmt.Println()


	// /* 
	// 	calling ecall_go_post_update_w
	// 	received update request
	// */
	// C.ecall_go_post_update_w(payment_num, &channel_ids[0], &amount[0], size);
 
	// fmt.Printf("[POST-UPDATE] CHANNEL 2 BALANCE: %d\n", C.ecall_get_balance_w(C.uint(2)))
	// fmt.Printf("[POST-UPDATE] CHANNEL 3 BALANCE: %d\n", C.ecall_get_balance_w(C.uint(3)))
	// fmt.Println()


	// /* 
	// 	calling ecall_go_idle_w
	// 	received payment confirmation
	// */
	// C.ecall_go_idle_w(10);

	// fmt.Printf("[AFTER] CHANNEL 2 BALANCE: %d\n", C.ecall_get_balance_w(C.uint(2)))
	// fmt.Printf("[AFTER] CHANNEL 3 BALANCE: %d\n", C.ecall_get_balance_w(C.uint(3)))


	// /* 
	// 	loading channel information from database
	// */
	// ChannelID := C.uint(9)
	// IsIn := C.uint(0)
	// ChannelStatus := C.uint(0)
	// MyAddr := []C.uchar("D03A2CC08755eC7D75887f0997195654b928893e")
	// MyDeposit := C.uint(88)
	// OtherDeposit := C.uint(0)
	// Balance := C.uint(80)
	// LockedBalance := C.uint(0)
	// OtherAddr := []C.uchar("0b4161ad4f49781a821c308d672e6c669139843c")
	// OtherIP := []C.uchar("123.12.1.2")
	// OtherPort := C.uint(7889)

    // C.ecall_load_channel_data_w(ChannelID, IsIn, ChannelStatus, &MyAddr[0], MyDeposit, OtherDeposit, Balance, LockedBalance, &OtherAddr[0], &OtherIP[0], OtherPort);
	// fmt.Printf("\nCHANNEL 9 BALANCE: %d\n", C.ecall_get_balance_w(C.uint(9)))
	

	// /* calling ecall_close_channel_w */
	// nonce = C.uint(0)
	// ChannelID = C.uint(9)
	// SigLen = C.uint(0)

	// var sig2 *C.uchar = C.ecall_close_channel_w(nonce, ChannelID, &SigLen)
	// hdr2 := reflect.SliceHeader{
	// 	Data: uintptr(unsafe.Pointer(sig2)),
	// 	Len:  int(SigLen),
	// 	Cap:  int(SigLen),
	// }

	// s2 := *(*[]C.uchar)(unsafe.Pointer(&hdr2))
	// for i := C.uint(0); i < SigLen; i++ {
    //     fmt.Printf("%02x", s2[i])
	// }
	// fmt.Println()

	
	/*
	storing sealed secret key to file
	*/

	// f := C.CString("./data/key/k1")
	// C.ecall_store_account_data_w(f)


	/*
	loading sealed secret key from file
	*/

	// C.ecall_load_account_data_w(f)


	/*
	storing sealed channel data to file
	*/

	f := C.CString("./data/channel/c2")
	C.ecall_store_channel_data_w(f)


	/*
	loading sealed channel data from file
	*/

	C.ecall_load_channel_data_w(f)


	/*
	get open channels
	*/
	
	// C.ecall_load_account_data_w()
	// C.ecall_load_channel_data_w()
	// var ochs unsafe.Pointer

    // ochs = C.ecall_get_open_channels_w()
    // channelSize := 68
	// channelSlice := (*[1 << 30]C.channel)(unsafe.Pointer(ochs))[:channelSize:channelSize]
	// fmt.Printf("채널 슬라이스 길이 : %d\n", cap(channelSlice))

	// fmt.Printf("%d\n", channelSlice[0].m_id)
	// fmt.Printf("%d\n", channelSlice[0].m_is_in)
	// fmt.Printf("%d\n", channelSlice[0].m_status)

	// var sig6 *C.uchar = &(channelSlice[0].m_my_addr[0])
	// hdr6 := reflect.SliceHeader{
	// 	Data: uintptr(unsafe.Pointer(sig6)),
	// 	Len:  int(20),
	// 	Cap:  int(20),
	// }

	// s6 := *(*[]C.uchar)(unsafe.Pointer(&hdr6))
	// for i := 0; i < 20; i++ {
	// 	fmt.Printf("%02x", s6[i])
	// }
	// fmt.Println()

	// fmt.Printf("%d\n", channelSlice[0].m_my_deposit)
	// fmt.Printf("%d\n", channelSlice[0].m_other_deposit)
	// fmt.Printf("%d\n", channelSlice[0].m_balance)
	// fmt.Printf("%d\n", channelSlice[0].m_locked_balance)

	// var sig7 *C.uchar = &(channelSlice[0].m_other_addr[0])
	// hdr7 := reflect.SliceHeader{
	// 	Data: uintptr(unsafe.Pointer(sig7)),
	// 	Len:  int(20),
	// 	Cap:  int(20),
	// }

	// s7 := *(*[]C.uchar)(unsafe.Pointer(&hdr7))
	// for i := 0; i < 20; i++ {
	// 	fmt.Printf("%02x", s7[i])
	// }

	// fmt.Println("\n========================================")


	// fmt.Printf("%d\n", channelSlice[1].m_id)
	// fmt.Printf("%d\n", channelSlice[1].m_is_in)
	// fmt.Printf("%d\n", channelSlice[1].m_status)

	// var sig8 *C.uchar = &(channelSlice[1].m_my_addr[0])
	// hdr8 := reflect.SliceHeader{
	// 	Data: uintptr(unsafe.Pointer(sig8)),
	// 	Len:  int(20),
	// 	Cap:  int(20),
	// }

	// s8 := *(*[]C.uchar)(unsafe.Pointer(&hdr8))
	// for i := 0; i < 20; i++ {
	// 	fmt.Printf("%02x", s8[i])
	// }
	// fmt.Println()

	// fmt.Println("--- 채널 정보들 ---")
	// fmt.Printf("%d\n", channelSlice[1].m_my_deposit)
	// fmt.Printf("%d\n", channelSlice[1].m_other_deposit)
	// fmt.Printf("%d\n", channelSlice[1].m_balance)
	// fmt.Printf("%d\n", channelSlice[1].m_locked_balance)
	// for i := 0; i < 20; i++{
	// 	fmt.Printf("%02x", channelSlice[1].m_other_addr[i])
	// }
	// fmt.Println()

	// var sig9 *C.uchar = &(channelSlice[1].m_other_addr[0])
	// hdr9 := reflect.SliceHeader{
	// 	Data: uintptr(unsafe.Pointer(sig9)),
	// 	Len:  int(20),
	// 	Cap:  int(20),
	// }

	// s9 := *(*[]C.uchar)(unsafe.Pointer(&hdr9))
	// for i := 0; i < 20; i++ {
	// 	fmt.Printf("%02x", s9[i])
	// }
	// fmt.Println()


	/*
	get public addresses
	*/
	// var paddrs unsafe.Pointer

    // paddrs = C.ecall_get_public_addrs_w()
    // paddrSize := 20
	// paddrSlice := (*[1 << 30]C.address)(unsafe.Pointer(paddrs))[:paddrSize:paddrSize]
	
	// var convertedAddress string
	// for i := 0; i < 20; i++ {
	// 	fmt.Printf("%02x", paddrSlice[1].addr[i])
	// }
	// convertedAddress = fmt.Sprintf("%02x", paddrSlice[0].addr)
	// fmt.Println("")
	// fmt.Println(convertedAddress)

	// fmt.Println()


	/*
	direct payment  ( Alice ----> Bob )
	*/
	// C.ecall_load_account_data_w()
	// C.ecall_load_channel_data_w()
	// // C.ecall_test_func_w()

	// var originalMsg *C.uchar
	// var signature *C.uchar

	// C.ecall_pay_w(8, 10, &originalMsg, &signature)   // Alice calls it

	// // char* S1 = reinterpret_cast<char*>(digest); 바꿔야 하나?
	// hdr9 := reflect.SliceHeader{
	// 	Data: uintptr(unsafe.Pointer(originalMsg)),
	// 	Len:  int(44),
	// 	Cap:  int(44),
	// }
	// s9 := *(*[]C.uchar)(unsafe.Pointer(&hdr9))
	// fmt.Println()
	// hdr10 := reflect.SliceHeader{
	// 	Data: uintptr(unsafe.Pointer(signature)),
	// 	Len:  int(65),
	// 	Cap:  int(65),
	// }
	// s10 := *(*[]C.uchar)(unsafe.Pointer(&hdr10))
	// originalMsgStr := fmt.Sprintf("%02x", s9)
	// signatureMsgStr := fmt.Sprintf("%02x", s10)
	
	// convertedOriginalMsg := &([]C.uchar(originalMsgStr)[0])
	// convertedSignatureMsg := &([]C.uchar(signatureMsgStr)[0])
	// fmt.Println(originalMsgStr)
	// fmt.Println(signatureMsgStr)
	// fmt.Println(convertedOriginalMsg)
	// fmt.Println(convertedSignatureMsg)

	// var reply_msg *C.uchar
	// var reply_sig *C.uchar

	// C.ecall_paid_w(convertedOriginalMsg, convertedSignatureMsg, &reply_msg, &reply_sig)   // Bob calls it
	// convertedAddress = fmt.Sprintf("%02x", paddrSlice[0].addr)
	// C.ecall_pay_accepted_w(reply_msg, reply_sig)   // Alice calls it
}