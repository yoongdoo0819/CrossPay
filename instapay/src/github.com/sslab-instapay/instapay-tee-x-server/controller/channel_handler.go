package controller

/*
#cgo CPPFLAGS: -I/home/yoongdoo0819/sgxsdk/include -I/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server
#cgo LDFLAGS: -L/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server -ltee

#include "app.h"
*/
import "C"

import (
	"context"
	"net/http"
	"time"
	"unsafe"
	"reflect"
	"sync"
//	"os"

	"github.com/gin-gonic/gin"
//	"github.com/sslab-instapay/instapay-tee-x-server/config"
	serverGrpc "github.com/sslab-instapay/instapay-tee-x-server/grpc"
        serverPb "github.com/sslab-instapay/instapay-tee-x-server/proto/server"
	xServerPb "github.com/sslab-instapay/instapay-tee-x-server/proto/cross-server"
	"google.golang.org/grpc"
	"github.com/sslab-instapay/instapay-tee-x-server/repository"
	"log"
	"fmt"
	"strconv"
	"math/rand"
)

var pn = 1
var rwMutex = new(sync.RWMutex)
var randValue int

func OpenChannelHandler(context *gin.Context)  {
	//channelName := context.PostForm("ch_name")
	//myAddress := context.PostForm("my_addr")
	//otherAddress := context.PostForm("other_addr")
	//deposit := context.PostForm("deposit")

	//TODO 채널 오픈 요청 컨트랙트와 ~~\

	context.JSON(http.StatusOK, gin.H{"message": "Channel"})
}

// TODO 데모 시나리오 이후 구현
func DepositChannelHandler(context *gin.Context) {
	context.JSON(http.StatusOK, gin.H{"message": "Channel"})
}

func DirectPayChannelHandler(context *gin.Context) {
	//channelId := context.PostForm("ch_id")
	//amount := context.PostForm("amount")

	context.JSON(http.StatusOK, gin.H{"message": "Channel"})
}

func CloseChannelHandler(context *gin.Context) {
	channelId, err := strconv.Atoi(context.PostForm("channelId"))

	if err != nil{
		log.Println(err)
	}

	channel, err := repository.GetChannelById(channelId)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(channel)

	//myBalance := channel.MyBalance


	context.JSON(http.StatusOK, gin.H{"message": "Channel"})
}

func PaymentToServerChannelHandler(context *gin.Context) {

	//otherAddress := context.PostForm("addr")
	//amount, err := strconv.Atoi(context.PostForm("amount"))
	//TODO 주소정보 셋팅
	//address := config.GetAccountConfig(1111)
	//if err != nil {
	//	log.Fatal(err)
	//}

	context.JSON(http.StatusOK, gin.H{"message": "Channel"})
}

func GetChannelListHandler(context *gin.Context){

	channelList, err := repository.GetChannelList()
	if err != nil {
		log.Fatal(channelList)
	}

	context.JSON(http.StatusOK, gin.H{
		"channels": channelList,
	})
}

/*
  instapay 3.0

*/
func CrossPaymentToServerChannelHandler(ctx *gin.Context) {

	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	randValue = r1.Intn(100)
	randValue = 1
//	fmt.Println(randValue)

	chain1From := ctx.PostForm("chain1_sender")
	chain1To := ctx.PostForm("chain1_receiver")
	chain1Val, err := strconv.Atoi(ctx.PostForm("chain1_sender_val"))
	if err != nil {
		log.Println(err)
	}

	if randValue < 50 {
	/*
		chain2From := ctx.PostForm("chain2_sender")
		chain2To := ctx.PostForm("chain2_receiver")
		chain2Val, err := strconv.Atoi(ctx.PostForm("chain2_sender_val"))
		if err != nil {
			log.Println(err)
		}

		chain3From := ctx.PostForm("chain3_sender")
		chain3To := ctx.PostForm("chain3_receiver")
		chain3Val, err := strconv.Atoi(ctx.PostForm("chain3_sender_val"))
		if err != nil {
			log.Println(err)
		}

		serverGrpc.ChainFrom = append(serverGrpc.ChainFrom, chain1From)
		serverGrpc.ChainTo = append(serverGrpc.ChainTo, chain1To)
		serverGrpc.ChainVal = append(serverGrpc.ChainVal, int64(chain1Val))

		serverGrpc.ChainFrom = append(serverGrpc.ChainFrom, chain2From)
		serverGrpc.ChainTo = append(serverGrpc.ChainTo, chain2To)
		serverGrpc.ChainVal = append(serverGrpc.ChainVal, int64(chain2Val))
	*/
	/*
		serverGrpc.ChainFrom = append(serverGrpc.ChainFrom, chain3From)
		serverGrpc.ChainTo = append(serverGrpc.ChainTo, chain3To)
		serverGrpc.ChainVal = append(serverGrpc.ChainVal, int64(chain3Val))
	*/
		chain1Sender := []C.uchar(chain1From)
		chain1Receiver := []C.uchar(chain1To)
		chain1Server := []C.uchar("c60f640c4505d15b972e6fc2a2a7cba09d05d9f7")

		chain2Sender := []C.uchar("f4444529d6221122d1712c52623ba119a60609e3")
		chain2Server := []C.uchar("d95da40bbd2001abf1a558c0b1dffd75940b8fd9")
		chain2Receiver := []C.uchar("73d8e5475278f7593b5293beaa45fb53f34c9ad2")

		//chain2Sender := []C.uchar(chain2From)
		//chain2Receiver := []C.uchar(chain2To)
		var PaymentNum C.uint
		//var originalMessage *C.uchar
		//var signature *C.uchar

	//	serverGrpc.StartTime = time.Now()
	//	rwMutex.Lock()

//		time.Sleep(5 * time.Millisecond)
		for ; ; {
			PaymentNum = C.ecall_cross_accept_request_w(
				&chain1Sender[0],
				&chain1Server[0],
				&chain1Receiver[0],
				C.uint(chain1Val),
				&chain2Sender[0],
				&chain2Server[0],
				&chain2Receiver[0],
				C.uint(chain1Val),
				&chain1Sender[0],
				&chain1Sender[0],
				&chain1Receiver[0],
				C.uint(pn))
				pn++

			if PaymentNum != 999999 {
				break
			}
		}

	/*
		if int(PaymentNum) != pn {
			fmt.Println("different pn")
			os.Exit(3)
		}
		pn++
	*/
	//	rwMutex.Unlock()

	//	fmt.Println(reflect.TypeOf(PaymentNum), reflect.TypeOf(pn))


	/*
		if PaymentNum == 0 || PaymentNum >= 30000 {
			fmt.Println(">>>>>>>>>>>> exit pn ", PaymentNum)
			os.Exit(3)
			return
		}
	*/
		//C.ecall_cross_add_participant_w(C.uint(PaymentNum), &([]C.uchar(chain1Server))[0])

	//	fmt.Println("===== CREATE CROSS ALL PREPARE MSG START =====")
	//	C.ecall_cross_create_all_prepare_req_msg_w(C.uint(PaymentNum), &originalMessage, &signature)
	//	fmt.Println("===== CREATE CROSS ALL PREPARE MSG END =====")

		//originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)
		connectionForCross_Server, err := grpc.Dial("141.223.121.164" + ":" + "50009", grpc.WithInsecure())
		if err != nil {
			log.Println(err)
			return
		}

		defer connectionForCross_Server.Close()

		client1 := xServerPb.NewCross_ServerClient(connectionForCross_Server)
		client1Context, cancel := context.WithTimeout(context.Background(), time.Second*180)
		defer cancel()

	/*
		C.ecall_cross_create_all_refund_req_msg_w(C.uint(pn), &originalMessage, &signature)
		originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)
	*/
	//	ctx.JSON(http.StatusOK, gin.H{"message":"Cross-Payment" })

		r, err := client1.CrossPaymentRequest(client1Context, &xServerPb.CrossPaymentMessage{Pn: int64(PaymentNum), ChainTo: serverGrpc.ChainTo, ChainFrom: serverGrpc.ChainFrom, ChainVal: serverGrpc.ChainVal})
		if err != nil {
			log.Println(err)
			return
		}

	//	fmt.Println(r.GetResult())

	/*
		for i:= 1; i<=1; i++ {
			go serverGrpc.WrapperCrossPaymentPrepareRequest(i, int64(PaymentNum), serverGrpc.ChainFrom[i], serverGrpc.ChainTo[i], int64(serverGrpc.ChainVal[i]), originalMessageByte, signatureByte)
		}
	*/
	/*
		var data = <- serverGrpc.ChComplete[int(PaymentNum)]
		if data == true {
			ctx.JSON(http.StatusOK, gin.H{"message":"Cross-Payment" })
		}
	*/

		if r.GetResult() == true {
			ctx.JSON(http.StatusOK, gin.H{"message":"Cross-Payment" })
		} else {
			ctx.JSON(http.StatusBadRequest, gin.H{"message":"Cross-Payment" })
		}

	} else if (randValue % 2) == 0 {
		//serverGrpc.Client[tempPaymentNum%100].PaymentRequest(serverGrpc.ClientContext[tempPaymentNum%100], &serverPb.PaymentRequestMessage{From: myAddress, To: otherAddress, Amount: int64(amount)})

		//ctx.JSON(http.StatusOK, gin.H{"message":"Cross-Payment" })

		connectionForCross_Server, err := grpc.Dial("141.223.121.169" + ":" + "50004", grpc.WithInsecure())
		if err != nil {
			log.Println(err)
			return
		}

		defer connectionForCross_Server.Close()

		client1 := serverPb.NewServerClient(connectionForCross_Server)
		client1Context, cancel := context.WithTimeout(context.Background(), time.Second*180)
		defer cancel()

	/*
		C.ecall_cross_create_all_refund_req_msg_w(C.uint(pn), &originalMessage, &signature)
		originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)
	*/
	//	ctx.JSON(http.StatusOK, gin.H{"message":"Cross-Payment" })

		r, err := client1.PaymentRequest(client1Context, &serverPb.PaymentRequestMessage{From: chain1From, To: chain1To, Amount: int64(chain1Val)})
		if err != nil {
			log.Println(err)
			return
		}
		
		if r.GetResult() == true {
			ctx.JSON(http.StatusOK, gin.H{"message":"Cross-Payment" })
		}
	} else if (randValue % 2) == 1 {

		connectionForCross_Server, err := grpc.Dial("141.223.121.165" + ":" + "50005", grpc.WithInsecure())
		if err != nil {
			log.Println(err)
			return
		}

		defer connectionForCross_Server.Close()

		client1 := serverPb.NewServerClient(connectionForCross_Server)
		client1Context, cancel := context.WithTimeout(context.Background(), time.Second*180)
		defer cancel()

	/*
		C.ecall_cross_create_all_refund_req_msg_w(C.uint(pn), &originalMessage, &signature)
		originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)
	*/
	//	ctx.JSON(http.StatusOK, gin.H{"message":"Cross-Payment" })

		r, err := client1.PaymentRequest(client1Context, &serverPb.PaymentRequestMessage{From: chain1From, To: chain1To, Amount: int64(chain1Val)})
		if err != nil {
			log.Println(err)
			return
		}

		if r.GetResult() == true {
			ctx.JSON(http.StatusOK, gin.H{"message":"Cross-Payment" })
		}
	}

}

func convertByteToPointer(originalMsg []byte, signature []byte) (*C.uchar, *C.uchar) {

	log.Println("----- convertByteToPointer Server Start -----")
	var uOriginal [44]C.uchar
	var uSignature [65]C.uchar

	for i := 0; i < 44; i++ {
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
		Len:  int(44),
		Cap:  int(44),
	}
	replyMsgS := *(*[]C.uchar)(unsafe.Pointer(&replyMsgHdr))

	replySigHdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(signature)),
		Len:  int(65),
		Cap:  int(65),
	}
	replySigS := *(*[]C.uchar)(unsafe.Pointer(&replySigHdr))

	for i := 0; i < 44; i++ {
		returnMsg = append(returnMsg, byte(replyMsgS[i]))
	}

	for i := 0; i < 65; i++ {
		returnSignature = append(returnSignature, byte(replySigS[i]))
	}

	return returnMsg, returnSignature
}


