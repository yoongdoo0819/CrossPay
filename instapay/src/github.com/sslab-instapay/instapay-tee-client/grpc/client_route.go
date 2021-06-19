package grpc

/*
#cgo CPPFLAGS: -I/home/yoongdoo0819/sgxsdk/include -I/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-client
#cgo LDFLAGS: -L/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-client -ltee

#include "app.h"
#include "message.h"
#include "cross_message.h"
#include "channel.h"
*/
/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

channel channels[100000];

void CExample(char *p) {     // 슬라이스를 void * 타입으로 받음
	printf("zz \n");
	printf("%c\n", p[0]); // H
	printf("%s\n", p);    // Hello, world!
}

void transition_to_go_pre_update(unsigned int index) 
{
	channels[index].m_status = PRE_UPDATE;
	//printf("channel id %d is PRE UPDATED \n", index);
}

unsigned int go_pre_update(unsigned char *msg, unsigned char *signature, unsigned char *original_msg, unsigned char *output)
{
	unsigned char *MY_ADDR = "f55ba9376db959fab2af86d565325829b08ea3c4";
	unsigned char reply_signature[65] = {0, };
	unsigned char *my_addr;

	unsigned int payment_num, payment_size;
	unsigned int *channel_ids;
	int *payment_amount;

	Message *ag_req = (Message*)msg;
	MessageRes reply;

	memset((unsigned char*)&reply, 0x00, sizeof(MessageRes));

	// verify_message

	if(ag_req->type != AG_REQ) {
		printf("NOT AG REQ \n");
		return 1;
	}

	payment_num = ag_req->payment_num;

	unsigned char *tempMyAddr;

	for(int i=0; i<3; i++) {
		tempMyAddr = ag_req->participant[i].party;
//		printf("addr : %s \n", tempMyAddr);

		if(!strcmp((char*)tempMyAddr, (char*)MY_ADDR)) {
//			printf("OK \n");
			payment_size = ag_req->participant[i].payment_size;
			channel_ids = ag_req->participant[i].channel_ids;
			payment_amount = ag_req->participant[i].payment_amount;

			break;
		}
	}

	for(int i=0; i<payment_size; i++) {
		//channels.find(channel_ids[i])->second.transition_to_go_pre_update();
//		printf("id : %d \n", channel_ids[i]);
		unsigned int channel_id = channel_ids[i];
		transition_to_go_pre_update(channel_id);

		if(payment_amount[i] < 0) {
			//channels.find(channel_ids[i])->second.m_locked_balance += payment_amount[i] * -1;
			channels[channel_ids[i]].m_locked_balance += payment_amount[i];
//			printf("id %d, locked bal %d \n", channel_ids[i], channels[channel_ids[i]].m_locked_balance);
			reply.amount = payment_amount[i] * -1;
		} else {
			reply.amount = payment_amount[i];
		}
	}

	//my_addr = channels.find(channel_ids[0])->second.m_my_addr;

	//std::vector<unsigned char> pubkey(my_addr, my_addr + 20);
	//std::vector<unsigned char> seckey;

	reply.type = AG_RES;
	reply.payment_num = payment_num;
	reply.e = 1;
	//seckey = accounts.find(pubkey)->second.get_seckey();

	//    printf("SIGN START \n");
	//sign_message((unsigned char*)&reply, sizeof(MessageRes), (unsigned char*)seckey.data(), reply_signature);
	//    printf("SIGN END \n");

	//memcpy(original_msg, (unsigned char*)&reply, sizeof(MessageRes));
	//memcpy(output, reply_signature, 65);

	//free(pubkey);
	//free(seckey);

	//    printf("PRE UPDATED \n");
	//*result = 9999;
	return 9999;
}

unsigned int go_post_update(unsigned char *msg, unsigned char *signature, unsigned char *senderMSG, unsigned char *senderSig, unsigned char *middleManMSG, unsigned char *middleManSig, unsigned char *receiverMSG, unsigned char *receiverSig, unsigned char *original_msg, unsigned char *output)
{
	unsigned char *MY_ADDR = "f55ba9376db959fab2af86d565325829b08ea3c4";
	unsigned char reply_signature[65] = {0, };
	unsigned char *my_addr;

	unsigned int payment_num, payment_size;
	unsigned int *channel_ids;
	int *payment_amount;

	Message *ud_req = (Message*)msg;
	MessageRes reply;

	memset((unsigned char*)&reply, 0x00, sizeof(MessageRes));

	// verify_message

	MessageRes *senderMsg = (MessageRes*)senderMSG;
	MessageRes *middleManMsg = (MessageRes*)middleManMSG;
	MessageRes *receiverMsg = (MessageRes*)receiverMSG;

	if(senderMsg->amount == middleManMsg->amount &&
	                    middleManMsg->amount == receiverMsg->amount) { 
	//	printf("same amount !! \n"); 
	}
	else { return 1; }

	if(ud_req->type != UD_REQ) {
		printf("NOT UD REQ \n");
		return 1;
	}

	payment_num = ud_req->payment_num;

	unsigned char *tempMyAddr;

	for(int i=0; i<3; i++) {
		tempMyAddr = ud_req->participant[i].party;
//		printf("addr : %s \n", tempMyAddr);

		if(!strcmp((char*)tempMyAddr, (char*)MY_ADDR)) {
//			printf("OK \n");
			payment_size = ud_req->participant[i].payment_size;
			channel_ids = ud_req->participant[i].channel_ids;
			payment_amount = ud_req->participant[i].payment_amount;

			break;
		}
	}

	unsigned int value;

	for(int i=0; i<payment_size; i++) {

		value = (payment_amount[i] < 0) ? payment_amount[i] * -1 : payment_amount[i];

		if(0 < payment_amount[i]) {
			channels[channel_ids[i]].m_balance += value; // paid			
			reply.amount = value;
			//          printf("reply.amount %d \n", value);
		}
		else {
			channels[channel_ids[i]].m_locked_balance += payment_amount[i];
			channels[channel_ids[i]].m_balance -= value; // pay

			reply.amount = value;
			//          printf("reply.amount %d \n", value);
		}

		channels[channel_ids[i]].m_status = POST_UPDATE;
//		printf("channel %d is post updated \n", channel_ids[i]);
	}

	//my_addr = channels.find(channel_ids[0])->second.m_my_addr;

	//std::vector<unsigned char> pubkey(my_addr, my_addr + 20);
	//std::vector<unsigned char> seckey;

	reply.type = AG_RES;
	reply.payment_num = payment_num;
	reply.e = 1;
	//seckey = accounts.find(pubkey)->second.get_seckey();

	//    printf("SIGN START \n");
	//sign_message((unsigned char*)&reply, sizeof(MessageRes), (unsigned char*)seckey.data(), reply_signature);
	//    printf("SIGN END \n");

	//memcpy(original_msg, (unsigned char*)&reply, sizeof(MessageRes));
	//memcpy(output, reply_signature, 65);

	//free(pubkey);
	//free(seckey);

	//    printf("PRE UPDATED \n");
	//*result = 9999;
	return 9999;
}

unsigned int go_idle(unsigned char *msg, unsigned char *signature, unsigned char *senderMSG, unsigned char *senderSig, unsigned char *middleManMSG, unsigned char *middleManSig, unsigned char *receiverMSG, unsigned char *receiverSig, unsigned char *original_msg, unsigned char *output)
{
	unsigned char *MY_ADDR = "f55ba9376db959fab2af86d565325829b08ea3c4";
	unsigned char reply_signature[65] = {0, };
	unsigned char *my_addr;

	unsigned int payment_num, payment_size;
	unsigned int *channel_ids;
	int *payment_amount;

	Message *confirm = (Message*)msg;
	MessageRes reply;

	memset((unsigned char*)&reply, 0x00, sizeof(MessageRes));

	// verify_message

	MessageRes *senderMsg = (MessageRes*)senderMSG;
	MessageRes *middleManMsg = (MessageRes*)middleManMSG;
	MessageRes *receiverMsg = (MessageRes*)receiverMSG;

	if(senderMsg->amount == middleManMsg->amount &&
	                    middleManMsg->amount == receiverMsg->amount) { 
	//	printf("same amount !! \n"); 
	}
	else { return 1; }

	if(confirm->type != CONFIRM) {
		printf("NOT CONFIRM REQ \n");
		return 1;
	}

	payment_num = confirm->payment_num;

	unsigned char *tempMyAddr;
	for(int i=0; i<3; i++) {
		tempMyAddr = confirm->participant[i].party;
//		printf("addr : %s \n", tempMyAddr);

		if(!strcmp((char*)tempMyAddr, (char*)MY_ADDR)) {
//			printf("OK \n");
			payment_size = confirm->participant[i].payment_size;
			channel_ids = confirm->participant[i].channel_ids;
			payment_amount = confirm->participant[i].payment_amount;

			break;
		}
	}

	unsigned int value;

	for(int i=0; i<payment_size; i++) {
		
		channels[channel_ids[i]].m_status = IDLE;
//		printf("channel %d is idle \n", channel_ids[i]);
	}

	return 9999;
}

unsigned int cross_go_pre_update(unsigned char *msg, unsigned char *signature, unsigned char *original_msg, unsigned char *output)
{
	unsigned char *MY_ADDR = "f55ba9376db959fab2af86d565325829b08ea3c4";
	unsigned char reply_signature[65] = {0, };
	unsigned char *my_addr;

	unsigned int payment_num, payment_size;
	unsigned int *channel_ids;
	int *payment_amount;

	Cross_Message *prepare_req = (Cross_Message*)msg;
	MessageRes reply;

	memset((unsigned char*)&reply, 0x00, sizeof(MessageRes));

	// verify_message

	if(prepare_req->type != CROSS_PREPARE_REQ) {
		printf("NOT CROSS_PREPARE_REQ \n");
		return 1;
	}

	payment_num = prepare_req->payment_num;

	unsigned char *tempMyAddr;

	for(int i=0; i<3; i++) {
		tempMyAddr = prepare_req->participant[i].party;
//		printf("addr : %s \n", tempMyAddr);

		if(!strcmp((char*)tempMyAddr, (char*)MY_ADDR)) {
//			printf("OK \n");
			payment_size = prepare_req->participant[i].payment_size;
			channel_ids = prepare_req->participant[i].channel_ids;
			payment_amount = prepare_req->participant[i].payment_amount;

			break;
		}
	}

	for(int i=0; i<payment_size; i++) {
		//channels.find(channel_ids[i])->second.transition_to_go_pre_update();
//		printf("id : %d \n", channel_ids[i]);

		channels[channel_ids[i]].m_cross_status = C_PRE;
//		printf("channel id %d is cross prepared \n", channel_ids[i]);

		if(payment_amount[i] < 0) {

			channels[channel_ids[i]].m_reserved_balance += payment_amount[i] * -1;
			channels[channel_ids[i]].m_balance -= payment_amount[i] * -1;

			//printf("id %d, reserved bal %d \n", channel_ids[i], channels[channel_ids[i]].m_reserved_balance);
			reply.amount = payment_amount[i] * -1;
		} else {
			reply.amount = payment_amount[i];
		}
	}

	//my_addr = channels.find(channel_ids[0])->second.m_my_addr;

	//std::vector<unsigned char> pubkey(my_addr, my_addr + 20);
	//std::vector<unsigned char> seckey;

	reply.type = AG_RES;
	reply.payment_num = payment_num;
	reply.e = 1;
	//seckey = accounts.find(pubkey)->second.get_seckey();

	//    printf("SIGN START \n");
	//sign_message((unsigned char*)&reply, sizeof(MessageRes), (unsigned char*)seckey.data(), reply_signature);
	//    printf("SIGN END \n");

	//memcpy(original_msg, (unsigned char*)&reply, sizeof(MessageRes));
	//memcpy(output, reply_signature, 65);

	//free(pubkey);
	//free(seckey);

	//    printf("PRE UPDATED \n");
	//*result = 9999;
	return 9999;
}

unsigned int cross_go_post_update(unsigned char *msg, unsigned char *signature, unsigned char *senderMSG, unsigned char *senderSig, unsigned char *middleManMSG, unsigned char *middleManSig, unsigned char *receiverMSG, unsigned char *receiverSig, unsigned char *original_msg, unsigned char *output)
{
	unsigned char *MY_ADDR = "f55ba9376db959fab2af86d565325829b08ea3c4";
	unsigned char reply_signature[65] = {0, };
	unsigned char *my_addr;

	unsigned int payment_num, payment_size;
	unsigned int *channel_ids;
	int *payment_amount;

	Cross_Message *ud_req = (Cross_Message*)msg;
	MessageRes reply;

	memset((unsigned char*)&reply, 0x00, sizeof(MessageRes));

	// verify_message

	MessageRes *senderMsg = (MessageRes*)senderMSG;
	MessageRes *middleManMsg = (MessageRes*)middleManMSG;
	MessageRes *receiverMsg = (MessageRes*)receiverMSG;

	if(senderMsg->amount == middleManMsg->amount &&
	                    middleManMsg->amount == receiverMsg->amount) { 
	//	printf("same amount !! \n"); 
	}
	else { return 1; }

	if(ud_req->type != CROSS_COMMIT_REQ) {
		printf("NOT CROSS_COMMIT_REQ \n");
		return 1;
	}

	payment_num = ud_req->payment_num;

	unsigned char *tempMyAddr;

	for(int i=0; i<3; i++) {
		tempMyAddr = ud_req->participant[i].party;
//		printf("addr : %s \n", tempMyAddr);

		if(!strcmp((char*)tempMyAddr, (char*)MY_ADDR)) {
//			printf("OK \n");
			payment_size = ud_req->participant[i].payment_size;
			channel_ids = ud_req->participant[i].channel_ids;
			payment_amount = ud_req->participant[i].payment_amount;

			break;
		}
	}

	unsigned int value;

	for(int i=0; i<payment_size; i++) {

		value = (payment_amount[i] < 0) ? payment_amount[i] * -1 : payment_amount[i];

		if(0 < payment_amount[i]) {
			channels[channel_ids[i]].m_reserved_balance += value; // paid			
			reply.amount = value;
			//          printf("reply.amount %d \n", value);
		}
		else {
			//channels[channel_ids[i]].m_locked_balance += payment_amount[i];
			//channels[channel_ids[i]].m_balance -= value; // pay

			reply.amount = value;
			//          printf("reply.amount %d \n", value);
		}

		channels[channel_ids[i]].m_cross_status = C_POST;
//		printf("channel %d is cross post updated \n", channel_ids[i]);
	}

	//my_addr = channels.find(channel_ids[0])->second.m_my_addr;

	//std::vector<unsigned char> pubkey(my_addr, my_addr + 20);
	//std::vector<unsigned char> seckey;

	reply.type = AG_RES;
	reply.payment_num = payment_num;
	reply.e = 1;
	//seckey = accounts.find(pubkey)->second.get_seckey();

	//    printf("SIGN START \n");
	//sign_message((unsigned char*)&reply, sizeof(MessageRes), (unsigned char*)seckey.data(), reply_signature);
	//    printf("SIGN END \n");

	//memcpy(original_msg, (unsigned char*)&reply, sizeof(MessageRes));
	//memcpy(output, reply_signature, 65);

	//free(pubkey);
	//free(seckey);

	//    printf("PRE UPDATED \n");
	//*result = 9999;
	return 9999;
}

unsigned int cross_go_idle(unsigned char *msg, unsigned char *signature, unsigned char *senderMSG, unsigned char *senderSig, unsigned char *middleManMSG, unsigned char *middleManSig, unsigned char *receiverMSG, unsigned char *receiverSig, unsigned char *original_msg, unsigned char *output)
{
	unsigned char *MY_ADDR = "f55ba9376db959fab2af86d565325829b08ea3c4";
	unsigned char reply_signature[65] = {0, };
	unsigned char *my_addr;

	unsigned int payment_num, payment_size;
	unsigned int *channel_ids;
	int *payment_amount;

	Cross_Message *confirm = (Cross_Message*)msg;
	MessageRes reply;

	memset((unsigned char*)&reply, 0x00, sizeof(MessageRes));

	// verify_message

	MessageRes *senderMsg = (MessageRes*)senderMSG;
	MessageRes *middleManMsg = (MessageRes*)middleManMSG;
	MessageRes *receiverMsg = (MessageRes*)receiverMSG;

	if(senderMsg->amount == middleManMsg->amount &&
	                    middleManMsg->amount == receiverMsg->amount) { 
	//	printf("same amount !! \n"); 
	}
	else { return 1; }

	if(confirm->type != CROSS_CONFIRM_REQ) {
		printf("NOT CROSS_CONFIRM_REQ \n");
		return 1;
	}

	payment_num = confirm->payment_num;

	unsigned char *tempMyAddr;
	for(int i=0; i<3; i++) {
		tempMyAddr = confirm->participant[i].party;
//		printf("addr : %s \n", tempMyAddr);

		if(!strcmp((char*)tempMyAddr, (char*)MY_ADDR)) {
//			printf("OK \n");
			payment_size = confirm->participant[i].payment_size;
			channel_ids = confirm->participant[i].channel_ids;
			payment_amount = confirm->participant[i].payment_amount;

			break;
		}
	}

	unsigned int value;

	for(int i=0; i<payment_size; i++) {
		unsigned int value = (payment_amount[i] < 0) ? payment_amount[i] * -1 : payment_amount[i];
		if(0 < payment_amount[i]) {
			channels[channel_ids[i]].m_reserved_balance -= value;
			channels[channel_ids[i]].m_balance += value;
			//channels.find(channel_ids[i])->second.paid(value);
		}
		else {
			channels[channel_ids[i]].m_reserved_balance -= value;
		}


		channels[channel_ids[i]].m_cross_status = IDLE;
//		printf("channel %d is cross idle \n", channel_ids[i]);
	}

	return 9999;
}

*/
import "C"

import (
	"context"
	//"encoding/hex"

	clientPb "github.com/sslab-instapay/instapay-tee-client/proto/client"

	// "github.com/sslab-instapay/instapay-tee-client/controller"
	"sync"
	"log"
	"fmt"
	"time"
	"reflect"
	"unsafe"

        "github.com/decred/dcrd/chaincfg/chainhash"
	//"github.com/decred/dcrd/dcrec/secp256k1"
	//"github.com/decred/dcrd/dcrec/secp256k1/schnorr"
//	"github.com/decred/dcrd/dcrec/secp256k1/v4"
//	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
	//      "github.com/decred/dcrd/dcrec/secp256k1/ecdsa"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	//"github.com/ethereum/go-ethereum/crypto"
	//"golang.org/x/crypto/sha3"
)

type MessageRes struct {
	/********* common *********/	    
	messageType C.uint
	amount C.uint
	payment_num C.uint
	e C.uint
} 


type Participant struct {

	party[41] C.uchar
	payment_size C.uint
        channel_ids[2] C.uint
	payment_amount[2] C.int
}

type Message struct {
	/********* common *********/
	messageType C.uint

	/***** direct payment *****/
	channel_id C.uint
	amount C.int
	counter C.uint

	/*** multi-hop payment ****/
	payment_num C.uint
	/*
	unsigned int payment_size;
	unsigned int channel_ids[2];
	int payment_amount[2];
	*/
	participant[3] Participant
	e C.uint
}

var seckey = []byte{7, 82, 123, 120, 27, 150, 39, 52, 92, 112, 78, 214, 183, 112, 19, 207, 128, 181, 72, 226, 125, 146, 63, 253, 47, 199, 191, 20, 132, 98, 119, 201}

//var Pn int64
var ChComplete [500000]chan bool
var chanCreateCheck = 0

var StartTime time.Time
var C_pre_yes int
var C_pre_no int
var C_post_yes int
var C_post_no int
var Addrs []string
var Amount int64

var rwMutex = new(sync.Mutex)

type ClientGrpc struct {
	clientPb.UnimplementedClientServer
}

func (s *ClientGrpc) AgreementRequest(ctx context.Context, in *clientPb.AgreeRequestsMessage) (*clientPb.AgreementResult, error) {
	//log.Println("----Receive Aggreement Request----")

//	fmt.Printf("pn %d starts \n", in.PaymentNumber)

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage, in.Signature)

	
	rwMutex.Lock()
	C.ecall_accpet_payments_w(C.uint(in.PaymentNumber))
	rwMutex.Unlock()

	var originalMsg *C.uchar
	var __signature[65] C.uchar
	var signature *C.uchar
//	rwMutex.Lock()

//	C.ecall_go_pre_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)
/*
	var Message = Message{}
	Message.messageType = 3

	Message.channel_id = 1
	Message.amount = 1
	Message.counter =0

	Message.payment_num = 1
	
	var party = "f55ba9376db959fab2af86d565325829b08ea3c4"
//	_sender := []C.uchar(party)
//	var data = []byte(party)
//	var abcd[41] C.uchar
//	abcd[0] = C.uchar(data[0])
//	abcd[1] = C.uchar(data[1])

	var Participant = Participant{}
//	C.memcpy(Participant.party, []C.uchar(&_sender[0]), 41)
	for i := 0; i < 40; i++ {
		Participant.party[i] = C.uchar(party[i])
	}


	Participant.payment_size = 1
        Participant.channel_ids[0] = 1
	Participant.payment_amount[0] = 1

	Message.participant[0] = Participant
	Message.participant[1] = Participant
	Message.participant[2] = Participant

	Message.e = 1
	_Message := (*C.uchar)(unsafe.Pointer(&Message))
*/

//	C.ecall_go_pre_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)

//	for ; ; {
//		result := C.ecall_go_pre_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)
		result := C.go_pre_update(convertedOriginalMsg, convertedSignatureMsg, nil, nil)

		var MessageRes = MessageRes{}
		MessageRes.messageType = C.uint(4)
		MessageRes.payment_num = C.uint(in.PaymentNumber)
		MessageRes.e = C.uint(1)
		MessageRes.amount = C.uint(1)

		originalMsg = (*C.uchar)(unsafe.Pointer(&MessageRes))
		signature = (*C.uchar)(unsafe.Pointer(&__signature))

		originalMessageByte, _ := convertMsgResPointerToByte(originalMsg, signature)
		messageHash := chainhash.HashB([]byte(originalMessageByte))
		//fmt.Println(messageHash)

		_signature, err := secp256k1.Sign(messageHash, seckey)
		if err != nil {
			fmt.Println("sign error ", err)
		}

		signature = (*C.uchar)(unsafe.Pointer(&_signature))

		if result == C.uint(1)  {
			fmt.Println("AG result failure!")
			return &clientPb.AgreementResult{Result: false}, nil
		} else if result == C.uint(9999) {
//			break
		}

		//fmt.Println("AG ################################## ")
		//defer C.free(unsafe.Pointer(originalMsg))
		//defer C.free(unsafe.Pointer(signature))

//	}

//	rwMutex.Unlock()
/*
	var uOriginal [44]C.uchar
        var uSignature [65]C.uchar

	for i := 0; i < 44; i++ {
		uOriginal[i] = 'a'
	}

	for i := 0; i < 65; i++ {
		uSignature[i] = 'b'
	}
*/
//	var originalMsg *C.uchar = (*C.uchar)(unsafe.Pointer(&uOriginal[0]))
//	var signature *C.uchar = (*C.uchar)(unsafe.Pointer(&uSignature[0]))

	originalMessageStr, signatureStr := convertMsgResPointerToByte(originalMsg, signature)

//	fmt.Println("msg : ", originalMessageStr)
//	fmt.Println("sig : ", signatureStr)

	return &clientPb.AgreementResult{Result: true, OriginalMessage: originalMessageStr, Signature: signatureStr}, nil
}

func (s *ClientGrpc) UpdateRequest(ctx context.Context, in *clientPb.UpdateRequestsMessage) (*clientPb.UpdateResult, error) {

//	return &clientPb.UpdateResult{Result: true}, nil

	// 채널 정보를 업데이트 한다던지 잔액을 변경.
//	log.Println("----Receive Update Request----")


	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage[0], in.Signature[0])
	convertedSenderMsg, convertedSenderSig := convertMsgResByteToPointer(in.OriginalMessage[1], in.Signature[1])
	convertedMiddleManMsg, convertedMiddleManSig := convertMsgResByteToPointer(in.OriginalMessage[2], in.Signature[2])
	convertedReceiverMsg, convertedReceiverSig := convertMsgResByteToPointer(in.OriginalMessage[3], in.Signature[3])

//	fmt.Println(convertedSenderMsg, convertedSenderSig)
//	fmt.Println(convertedMiddleManMsg, convertedMiddleManSig)
//	fmt.Println(convertedReceiverMsg, convertedReceiverSig)

//	fmt.Println(in.OriginalMessage[1], convertedSenderSig)
//	fmt.Println(in.OriginalMessage[2], convertedMiddleManSig)
//	fmt.Println(in.OriginalMessage[3], convertedReceiverSig)

/*
	var convertedCrossPaymentMsg, convertedCrossPaymentSig *C.uchar
	if in.OriginalMessage[4] != nil {
		convertedCrossPaymentMsg, convertedCrossPaymentSig = convertMsgResByteToPointer(in.OriginalMessage[4], in.Signature[4])
	}
*/
	var originalMsg *C.uchar
        var __signature[65] C.uchar
	var signature *C.uchar

//	C.ecall_go_post_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)

//	rwMutex.Lock()

//	for ; ; {
//		result := C.ecall_go_post_update_w(convertedOriginalMsg, convertedSignatureMsg, convertedSenderMsg, convertedSenderSig, convertedMiddleManMsg, convertedMiddleManSig, convertedReceiverMsg, convertedReceiverSig, nil, nil, &originalMsg, &signature)

		result := C.go_post_update(convertedOriginalMsg, convertedSignatureMsg, convertedSenderMsg, convertedSenderSig, convertedMiddleManMsg, convertedMiddleManSig, convertedReceiverMsg, convertedReceiverSig, nil, nil)

		var MessageRes = MessageRes{}
		MessageRes.messageType = C.uint(6)
		MessageRes.payment_num = C.uint(in.PaymentNumber)
		MessageRes.e = C.uint(1)
		MessageRes.amount = C.uint(1)

		originalMsg = (*C.uchar)(unsafe.Pointer(&MessageRes))
		signature = (*C.uchar)(unsafe.Pointer(&__signature))

		originalMessageByte, _ := convertMsgResPointerToByte(originalMsg, signature)
		messageHash := chainhash.HashB([]byte(originalMessageByte))
//		fmt.Println(messageHash)

		_signature, err := secp256k1.Sign(messageHash, seckey)
		if err != nil {
			fmt.Println("sign error ", err)
		}

		signature = (*C.uchar)(unsafe.Pointer(&_signature))

		if result == C.uint(1) {
			fmt.Println("UD result failure!")
			return &clientPb.UpdateResult{Result: false}, nil
		} else if result == C.uint(9999) {
			//break
		}
		//fmt.Println("UD ################################## ")

		//defer C.free(unsafe.Pointer(originalMsg))
		//defer C.free(unsafe.Pointer(signature))
//	}

//	rwMutex.Unlock()

	originalMessageStr, signatureStr := convertMsgResPointerToByte(originalMsg, signature)

//	fmt.Printf("pn %d ends \n", in.PaymentNumber)
	return &clientPb.UpdateResult{Result: true, OriginalMessage: originalMessageStr, Signature: signatureStr}, nil
}

func (s *ClientGrpc) ConfirmPayment(ctx context.Context, in *clientPb.ConfirmRequestsMessage) (*clientPb.ConfirmResult, error) {
//	log.Println("----ConfirmPayment Request Receive----")

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage[0], in.Signature[0])
	convertedSenderMsg, convertedSenderSig := convertMsgResByteToPointer(in.OriginalMessage[1], in.Signature[1])
	convertedMiddleManMsg, convertedMiddleManSig := convertMsgResByteToPointer(in.OriginalMessage[2], in.Signature[2])
	convertedReceiverMsg, convertedReceiverSig := convertMsgResByteToPointer(in.OriginalMessage[3], in.Signature[3])

//	fmt.Println(convertedSenderMsg, convertedSenderSig)
//	fmt.Println(convertedMiddleManMsg, convertedMiddleManSig)
//	fmt.Println(convertedReceiverMsg, convertedReceiverSig)

//	C.ecall_go_idle_w(convertedOriginalMsg, convertedSignatureMsg)

//	rwMutex.Lock()
/*
	var convertedCrossPaymentMsg, convertedCrossPaymentSig *C.uchar
	if in.OriginalMessage[4] != nil {
		convertedCrossPaymentMsg, convertedCrossPaymentSig = convertMsgResByteToPointer(in.OriginalMessage[4], in.Signature[4])
	}
*/
//	for ; ; {
//		result := C.ecall_go_idle_w(convertedOriginalMsg, convertedSignatureMsg, convertedSenderMsg, convertedSenderSig, convertedMiddleManMsg, convertedMiddleManSig, convertedReceiverMsg, convertedReceiverSig, nil, nil)


		result := C.go_idle(convertedOriginalMsg, convertedSignatureMsg, convertedSenderMsg, convertedSenderSig, convertedMiddleManMsg, convertedMiddleManSig, convertedReceiverMsg, convertedReceiverSig, nil, nil)

		if result == 1 {
			fmt.Println("CONFIRM result failure!")
			return &clientPb.ConfirmResult{Result: false}, nil
		} else if result == 9999  {
//			break
		}

		//fmt.Println("CONFIRM ################################## ")

//	}

//	rwMutex.Unlock()

//	log.Println("----ConfirmPayment Request End----")

	// fmt.Println(C.ecall_get_balance_w(C.uint(1)))
	// fmt.Println(C.ecall_get_balance_w(C.uint(2)))
	// fmt.Println(time.Since(controller.ExecutionTime))

//	var pn = in.PaymentNumber
//	ChComplete[pn] <- true

	//fmt.Println("?")
	return &clientPb.ConfirmResult{Result: true}, nil
}

func (s *ClientGrpc) DirectChannelPayment(ctx context.Context, in *clientPb.DirectChannelPaymentMessage) (*clientPb.DirectPaymentResult, error) {
	log.Println("----Direct Channel Payment Request Receive----")

	log.Println("--- Start Byte to Pointer ---")
	originalMessagePointer, signaturePointer := convertByteToPointer(in.OriginalMessage, in.Signature)
	fmt.Println(originalMessagePointer, signaturePointer)
	log.Println("--- End Byte to Pointer ---")
	var replyMessage *C.uchar
	var replySignature *C.uchar

	//C.ecall_paid_w(originalMessagePointer, signaturePointer, &replyMessage, &replySignature)
	log.Println("----Direct Channel Payment Request End----")

	convertedReplyMessage, convertedReplySignature := convertPointerToByte(replyMessage, replySignature)

	//defer C.free(unsafe.Pointer(replyMessage))
	//defer C.free(unsafe.Pointer(replySignature))

	return &clientPb.DirectPaymentResult{Result: true, ReplyMessage: convertedReplyMessage, ReplySignature: convertedReplySignature}, nil
}

func convertByteToPointer(originalMsg []byte, signature []byte) (*C.uchar, *C.uchar) {

	var uOriginal [216]C.uchar
	var uSignature [65]C.uchar

	for i := 0; i < 216; i++ {
		uOriginal[i] = C.uchar(originalMsg[i])
	}

	for i := 0; i < 65; i++ {
		uSignature[i] = C.uchar(signature[i])
	}

	cOriginalMsg := (*C.uchar)(unsafe.Pointer(&uOriginal[0]))
	cSignature := (*C.uchar)(unsafe.Pointer(&uSignature[0]))

	return cOriginalMsg, cSignature
}

func convertMsgResByteToPointer(originalMsg []byte, signature []byte) (*C.uchar, *C.uchar) {

	var uOriginal [16]C.uchar
	var uSignature [65]C.uchar

	for i := 0; i < 16; i++ {
		uOriginal[i] = C.uchar(originalMsg[i])
	}

	for i := 0; i < 65; i++ {
		uSignature[i] = C.uchar(signature[i])
	}

	cOriginalMsg := (*C.uchar)(unsafe.Pointer(&uOriginal[0]))
	cSignature := (*C.uchar)(unsafe.Pointer(&uSignature[0]))

	return cOriginalMsg, cSignature
}
func convertPointerToByte(originalMsg *C.uchar, signature *C.uchar) ([]byte, []byte) {

	var returnMsg []byte
	var returnSignature []byte

	replyMsgHdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(originalMsg)),
		Len:  int(216),
		Cap:  int(216),
	}
	replyMsgS := *(*[]C.uchar)(unsafe.Pointer(&replyMsgHdr))

	replySigHdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(signature)),
		Len:  int(65),
		Cap:  int(65),
	}
	replySigS := *(*[]C.uchar)(unsafe.Pointer(&replySigHdr))

	for i := 0; i < 216; i++ {
		returnMsg = append(returnMsg, byte(replyMsgS[i]))
	}

	for i := 0; i < 65; i++ {
		returnSignature = append(returnSignature, byte(replySigS[i]))
	}

//	defer C.free(unsafe.Pointer(originalMsg))
//	defer C.free(unsafe.Pointer(signature))

	return returnMsg, returnSignature
}

func convertMsgResPointerToByte(originalMsg *C.uchar, signature *C.uchar) ([]byte, []byte) {

	var returnMsg []byte
	var returnSignature []byte

	replyMsgHdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(originalMsg)),
		Len:  int(16),
		Cap:  int(16),
	}
	replyMsgS := *(*[]C.uchar)(unsafe.Pointer(&replyMsgHdr))

	replySigHdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(signature)),
		Len:  int(65),
		Cap:  int(65),
	}
	replySigS := *(*[]C.uchar)(unsafe.Pointer(&replySigHdr))

	for i := 0; i < 16; i++ {
		returnMsg = append(returnMsg, byte(replyMsgS[i]))
	}

	for i := 0; i < 65; i++ {
		returnSignature = append(returnSignature, byte(replySigS[i]))
	}

	//defer C.free(unsafe.Pointer(originalMsg))
	//defer C.free(unsafe.Pointer(signature))

	return returnMsg, returnSignature
}
/*
 *
 *
 * InstaPay 3.0
 */

func (s *ClientGrpc) CrossPaymentPrepareClientRequest(ctx context.Context, in *clientPb.CrossPaymentPrepareReqClientMessage) (*clientPb.PrepareResult, error) {
	//log.Println("----CROSS PAYMENT PREPARE START IN CLIENT----")


	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage, in.Signature)

	rwMutex.Lock()
//	C.ecall_cross_go_pre_update_two_w(C.uint(in.PaymentNumber))
	rwMutex.Unlock()

	var originalMsg *C.uchar
	//var __signature[65] C.uchar
	var signature *C.uchar

	Addrs = in.Addr
        Amount = in.Amount
/*
	for {

		if C_pre_yes == 1 {
			break
		} else if C_pre_yes == 2 {
			C_pre_yes = 0
			return &clientPb.PrepareResult{Result: false}, nil

		}
	}
*/
	for ; ; {
		result := C.ecall_cross_go_pre_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)

//		originalMessageStr, signatureStr := convertMsgResPointerToByte(originalMsg, signature)
//		fmt.Println("signature : ", in.Signature)

/*		result := C.cross_go_pre_update(convertedOriginalMsg, convertedSignatureMsg, nil, nil)

		var MessageRes = MessageRes{}
		MessageRes.messageType = C.uint(8)
		MessageRes.payment_num = C.uint(in.PaymentNumber)
		MessageRes.e = C.uint(1)
		MessageRes.amount = C.uint(1)

		originalMsg = (*C.uchar)(unsafe.Pointer(&MessageRes))
		signature = (*C.uchar)(unsafe.Pointer(&__signature))

		originalMessageByte, _ := convertMsgResPointerToByte(originalMsg, signature)
		//fmt.Println(originalMessageStr, originalMessageByte)
		//fmt.Println(signatureStr)

		//messageHash := crypto.Keccak256(originalMessageByte)
		//h.Write(originalMessageByte)
		//messageHash := h.Sum(nil)

		messageHash := chainhash.HashB([]byte(originalMessageByte))
//		messageHash := []byte("24bb5f9477d980bac42d698307d096ce183d6d557c3c1613404a2a174ba66ce")
		//fmt.Println(messageHash)
		_signature, err := secp256k1.Sign(messageHash, seckey)
		if err != nil {
			fmt.Println("sign error ", err)
		}

		signature = (*C.uchar)(unsafe.Pointer(&_signature))
		//fmt.Println("sig >> ", signatureStr, _signature)
/*
		pkBytes, err := hex.DecodeString("5a5e2194e0639fd017158793812dd5f5668f5bfc9a146f93f39237a4b4ed7dd5")
//			"22a47fa09a223f2aa079edf85a7c2d4f87" +
//		"20ee63e502ee2869afab7de234b80c")
		if err != nil {
			fmt.Println(err)
			//return
		}
		privKey := secp256k1.PrivKeyFromBytes(pkBytes)

		pubKey := privKey.PubKey()
		fmt.Println(pubKey)
//		verified := secp256k1.VerifySignature(pubKey, messageHash, in.Signature)
/*
		privKey := secp256k1.PrivKeyFromBytes(pkBytes)
		fmt.Println(privKey)
		// Sign a message using the private key.
		message := in.OriginalMessage//"test message"
		messageHash := chainhash.HashB([]byte(message))
		signature, err := schnorr.Sign(privKey, messageHash)

		if err != nil {
			fmt.Println(err)
			//return
		}

		// Serialize and display the signature.
		fmt.Printf("Serialized Signature: %x\n", signature.Serialize())
		fmt.Println(signature.Serialize())
		fmt.Println(in.Signature)
		// Verify the signature for the message using the public key.
		pubKey := privKey.PubKey()
		fmt.Println(pubKey)
		fmt.Println(reflect.TypeOf(signature))

//		sig := (schnorr.Signature*) in.Signature
		StartTime = time.Now()
		verified := signature.Verify(messageHash, pubKey)
		fmt.Printf("Signature Verified? %v\n", verified)

		signature, err = schnorr.ParseSignature(in.Signature)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Println(reflect.TypeOf(signature))

		verified = signature.Verify(messageHash, pubKey)

		elapsedTime := time.Since(StartTime)
		fmt.Println(elapsedTime)

		fmt.Printf("Signature Verified? %v\n", verified)
*/
		if result == 1 {
			fmt.Println("PREPARE result failure!")
			return &clientPb.PrepareResult{Result: false}, nil
		} else if result == 9999  {
			break
		}

		//fmt.Println("AG ################################## ")
		defer C.free(unsafe.Pointer(originalMsg))
		defer C.free(unsafe.Pointer(signature))

	}

	originalMessageStr, signatureStr := convertMsgResPointerToByte(originalMsg, signature)

//	fmt.Println("sig : ", signatureStr)



	return &clientPb.PrepareResult{Result: true, OriginalMessage: originalMessageStr, Signature: signatureStr}, nil
}

func (s *ClientGrpc) CrossPaymentCommitClientRequest(ctx context.Context, in *clientPb.CrossPaymentCommitReqClientMessage) (*clientPb.CommitResult, error) {

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage[0], in.Signature[0])
	convertedSenderMsg, convertedSenderSig := convertMsgResByteToPointer(in.OriginalMessage[1], in.Signature[1])
	convertedMiddleManMsg, convertedMiddleManSig := convertMsgResByteToPointer(in.OriginalMessage[2], in.Signature[2])
	convertedReceiverMsg, convertedReceiverSig := convertMsgResByteToPointer(in.OriginalMessage[3], in.Signature[3])


/*
	var convertedCrossPaymentMsg, convertedCrossPaymentSig *C.uchar
	if in.OriginalMessage[4] != nil {
		convertedCrossPaymentMsg, convertedCrossPaymentSig = convertMsgResByteToPointer(in.OriginalMessage[4], in.Signature[4])
	}
*/
	var originalMsg *C.uchar
	//var __signature[65] C.uchar
	var signature *C.uchar

//	C.ecall_go_post_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)

//	rwMutex.Lock()

	for ; ; {
		result := C.ecall_cross_go_post_update_w(convertedOriginalMsg, convertedSignatureMsg, convertedSenderMsg, convertedSenderSig, convertedMiddleManMsg, convertedMiddleManSig, convertedReceiverMsg, convertedReceiverSig, nil, nil, &originalMsg, &signature)
/*
		result := C.cross_go_post_update(convertedOriginalMsg, convertedSignatureMsg, convertedSenderMsg, convertedSenderSig, convertedMiddleManMsg, convertedMiddleManSig, convertedReceiverMsg, convertedReceiverSig, nil, nil)

		var MessageRes = MessageRes{}
		MessageRes.messageType = C.uint(9)
		MessageRes.payment_num = C.uint(in.PaymentNumber)
		MessageRes.e = C.uint(1)
		MessageRes.amount = C.uint(1)

		originalMsg = (*C.uchar)(unsafe.Pointer(&MessageRes))
		signature = (*C.uchar)(unsafe.Pointer(&__signature))

		originalMessageByte, _ := convertMsgResPointerToByte(originalMsg, signature)
		messageHash := chainhash.HashB([]byte(originalMessageByte))

		_signature, err := secp256k1.Sign(messageHash, seckey)
		if err != nil {
			fmt.Println("sign error ", err)
		}

		signature = (*C.uchar)(unsafe.Pointer(&_signature))
*/
		if result == 1 {
			fmt.Println("COMMIT result failure!")
			return &clientPb.CommitResult{Result: false}, nil
		} else if result == 9999  {
			break
		}
		//fmt.Println("UD ################################## ")

		defer C.free(unsafe.Pointer(originalMsg))
		defer C.free(unsafe.Pointer(signature))
	}

//	rwMutex.Unlock()

	originalMessageStr, signatureStr := convertMsgResPointerToByte(originalMsg, signature)
//	fmt.Println("COMMIT !!")
	return &clientPb.CommitResult{Result: true, OriginalMessage: originalMessageStr, Signature: signatureStr}, nil

	// 채널 정보를 업데이트 한다던지 잔액을 변경.
//	time.Sleep(time.Second * 50)
//	log.Println("----CROSS PAYMENT COMMIT START IN CLIENT----")
/*
	for {
		if C_post_yes == 1 {
			break
		}
		
		if C_post_yes == 2 {
			C_post_yes = 0
			return &clientPb.CommitResult{Result: false}, nil

		}
	}
*/
/*
	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage, in.Signature)

	var originalMsg *C.uchar
	var signature *C.uchar

//	rwMutex.Lock()
	C.ecall_cross_go_post_update_w(convertedOriginalMsg, convertedSignatureMsg, &originalMsg, &signature)
//	rwMutex.Unlock()

	originalMessageStr, signatureStr := convertPointerToByte(originalMsg, signature)

	C_post_yes = 0
	log.Println("----CROSS PAYMENT COMMIT END IN CLIENT----")
	return &clientPb.CommitResult{Result: true, OriginalMessage: originalMessageStr, Signature: signatureStr}, nil
	*/
}

func (s *ClientGrpc) CrossPaymentConfirmClientRequest(ctx context.Context, in *clientPb.CrossPaymentConfirmReqClientMessage) (*clientPb.ConfirmResult, error) {

//	log.Println("----CROSS PAYMENT CONFIRM IN CLIENT----")

	convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage[0], in.Signature[0])
	convertedSenderMsg, convertedSenderSig := convertMsgResByteToPointer(in.OriginalMessage[1], in.Signature[1])
	convertedMiddleManMsg, convertedMiddleManSig := convertMsgResByteToPointer(in.OriginalMessage[2], in.Signature[2])
	convertedReceiverMsg, convertedReceiverSig := convertMsgResByteToPointer(in.OriginalMessage[3], in.Signature[3])


//	C.ecall_go_idle_w(convertedOriginalMsg, convertedSignatureMsg)

//	rwMutex.Lock()
/*
	var convertedCrossPaymentMsg, convertedCrossPaymentSig *C.uchar
	if in.OriginalMessage[4] != nil {
		convertedCrossPaymentMsg, convertedCrossPaymentSig = convertMsgResByteToPointer(in.OriginalMessage[4], in.Signature[4])
	}
*/
	for ; ; {
		result := C.ecall_cross_go_idle_w(convertedOriginalMsg, convertedSignatureMsg, convertedSenderMsg, convertedSenderSig, convertedMiddleManMsg, convertedMiddleManSig, convertedReceiverMsg, convertedReceiverSig, nil, nil)

/*
		result := C.cross_go_idle(convertedOriginalMsg, convertedSignatureMsg, convertedSenderMsg, convertedSenderSig, convertedMiddleManMsg, convertedMiddleManSig, convertedReceiverMsg, convertedReceiverSig, nil, nil)
*/
		if result == 1 {
			fmt.Println("CONFIRM result failure!")
			return &clientPb.ConfirmResult{Result: false}, nil
		} else if result == 9999  {
			break
		}

		//fmt.Println("CONFIRM ################################## ")

	}

//	rwMutex.Unlock()

//	log.Println("----ConfirmPayment Request End----")

	// fmt.Println(C.ecall_get_balance_w(C.uint(1)))
	// fmt.Println(C.ecall_get_balance_w(C.uint(2)))
	// fmt.Println(time.Since(controller.ExecutionTime))

//	var pn = in.PaymentNumber
//	ChComplete[pn] <- true

	//fmt.Println("?")
	return &clientPb.ConfirmResult{Result: true}, nil
//	time.Sleep(time.Second * 50)

	//convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage, in.Signature)

//	rwMutex.Lock()
	//C.ecall_cross_go_idle_w(convertedOriginalMsg, convertedSignatureMsg)
//	rwMutex.Unlock()

        log.Println("----CROSS PAYMENT CONFIRM END IN CLIENT----")

	elapsedTime := time.Since(StartTime)
	fmt.Println("execution time : ", elapsedTime.Seconds())
	fmt.Printf("execution time : %s", elapsedTime)


	// fmt.Println(C.ecall_get_balance_w(C.uint(1)))
	// fmt.Println(C.ecall_get_balance_w(C.uint(2)))
	// fmt.Println(time.Since(controller.ExecutionTime))

	Amount = 0
	Addrs = nil
	return &clientPb.ConfirmResult{Result: true}, nil
}

func (s *ClientGrpc) CrossPaymentRefundClientRequest(ctx context.Context, in *clientPb.CrossPaymentRefundReqClientMessage) (*clientPb.RefundResult, error) {

	log.Println("----CROSS PAYMENT REFUND IN CLIENT----")
//	time.Sleep(time.Second * 50)

	//convertedOriginalMsg, convertedSignatureMsg := convertByteToPointer(in.OriginalMessage, in.Signature)
	//C.ecall_cross_refund_w(convertedOriginalMsg, convertedSignatureMsg)
        log.Println("----CROSS PAYMENT REFUND END IN CLIENT----")

	elapsedTime := time.Since(StartTime)
	fmt.Println("execution time : ", elapsedTime.Seconds())
	fmt.Printf("execution time : %s", elapsedTime)

	// fmt.Println(C.ecall_get_balance_w(C.uint(1)))
	// fmt.Println(C.ecall_get_balance_w(C.uint(2)))
	// fmt.Println(time.Since(controller.ExecutionTime))

	Amount = 0
	Addrs = nil
	return &clientPb.RefundResult{Result: true}, nil
}


func ChanCreate() {

	fmt.Println("ChanCreate! ")

	if chanCreateCheck == 0{
		var i = 0
		for i = range ChComplete {
			//ch[i] = make(chan bool)
			ChComplete[i] = make(chan bool)
		}
		fmt.Printf("%d ChanCreate! \n", i)
	} else {
		return
	}

	chanCreateCheck = 1
}

