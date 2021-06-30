package controller

/*
#cgo CPPFLAGS: -I/home/yoongdoo0819/sgxsdk/include -I/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server
#cgo LDFLAGS: -L/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server -ltee

#include "app.h"
*/
import "C"

import (
	//"context"
	"net/http"
	//"time"
	"unsafe"
	"reflect"
	"sync"
//	"os"

	"github.com/gin-gonic/gin"
//	"github.com/sslab-instapay/instapay-tee-x-server/config"
	serverGrpc "github.com/sslab-instapay/instapay-tee-x-server/grpc"
        //serverPb "github.com/sslab-instapay/instapay-tee-x-server/proto/server"
	xServerPb "github.com/sslab-instapay/instapay-tee-x-server/proto/cross-server"
	//"google.golang.org/grpc"
	"github.com/sslab-instapay/instapay-tee-x-server/repository"
	"log"
	"fmt"
	"strconv"
	//"math/rand"
	//pbClient "github.com/sslab-instapay/instapay-tee-x-server/proto/client"

)

//var connection, err = grpc.Dial("141.223.121.167:50001", grpc.WithInsecure())

var cnt = 0
var counter = 0
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

//	serverGrpc.StartTime = time.Now()
//	serverGrpc.ChainFrom = /*ctx.PostForm("chain1_sender")*/ append(serverGrpc.ChainFrom, ctx.PostForm("chain1_sender"))
//	serverGrpc.ChainTo = /*ctx.PostForm("chain1_receiver")*/append(serverGrpc.ChainTo, ctx.PostForm("chain1_receiver"))
//	val, err :=  strconv.Atoi(ctx.PostForm("chain1_sender_val"))
//	serverGrpc.ChainVal = /*int64(val)*/ append(serverGrpc.ChainVal, int64(val))
/*
	serverGrpc.ChainFrom = append(serverGrpc.ChainFrom, ctx.PostForm("chain2_sender"))
	serverGrpc.ChainTo = append(serverGrpc.ChainTo, ctx.PostForm("chain2_receiver"))
	val, err = strconv.Atoi(ctx.PostForm("chain2_sender_val"))
	serverGrpc.ChainVal = append(serverGrpc.ChainVal, int64(val))

	if err != nil {
		log.Println(err)
	}
*/
	chain1From := ctx.PostForm("chain1_sender")
	chain1To := ctx.PostForm("chain1_receiver")
	chain1Val, err := strconv.Atoi(ctx.PostForm("chain1_sender_val"))
	if err != nil {
		log.Println(err)
	}
	chain2From := ctx.PostForm("chain2_sender")
	chain2To := ctx.PostForm("chain2_receiver")
	chain2Val, err := strconv.Atoi(ctx.PostForm("chain2_sender_val"))

	chain1Sender := []C.uchar(chain1From)
	chain1Receiver := []C.uchar(chain1To)
	chain1Server := []C.uchar("c60f640c4505d15b972e6fc2a2a7cba09d05d9f7")

	chain2Sender := []C.uchar(chain2From)//"f4444529d6221122d1712c52623ba119a60609e3")
	chain2Server := []C.uchar("d95da40bbd2001abf1a558c0b1dffd75940b8fd9")
	chain2Receiver := []C.uchar(chain2To)//"73d8e5475278f7593b5293beaa45fb53f34c9ad2")

/*
	chain1Sender := []C.uchar(serverGrpc.ChainFrom[0])
	chain1Receiver := []C.uchar(serverGrpc.ChainTo[0])
	chain1Server := []C.uchar(serverGrpc.ChainTo[0])

	chain2Sender := []C.uchar(serverGrpc.ChainFrom[1])
	chain2Server := []C.uchar(serverGrpc.ChainTo[1])
	chain2Receiver := []C.uchar(serverGrpc.ChainTo[1])
*/
	//chain2Sender := []C.uchar(chain2From)
	//chain2Receiver := []C.uchar(chain2To)

	var PaymentNum C.uint
	for ; ; {
		PaymentNum = C.ecall_cross_accept_request_w(
			&chain1Sender[0],
			&chain1Server[0],
			&chain1Receiver[0],
			C.uint(chain1Val),//serverGrpc.ChainVal[0]),
			&chain2Sender[0],
			&chain2Server[0],
			&chain2Receiver[0],
			C.uint(chain2Val),//serverGrpc.ChainVal[1]),
			nil,
			nil,
			nil,
			C.uint(pn))
			rwMutex.Lock()
			pn++
			rwMutex.Unlock()

		if PaymentNum != 999999 {
			break
		}

	}
/*
	var wg sync.WaitGroup
	var cnt=0

	for i:=0; i<6; i++ {
		wg.Add(1)
		go func() {
			//client := pbClient.NewClientClient(connectionForClient[clientAddr[address]])
		//	var connection, err = grpc.Dial("141.223.121.167:50001", grpc.WithInsecure())
			client := pbClient.NewClientClient(connection)
			if client == nil {
				log.Fatal("client conn err")

			}

			_, err := client.CrossPaymentPrepareClientRequest(context.Background(), &pbClient.CrossPaymentPrepareReqClientMessage{PaymentNumber: int64(pn), OriginalMessage : []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") })

			if err != nil {
				log.Println("client AgreementRequest err : ", err)// clientAddr[address])
			}
			rwMutex.Lock()
			cnt++
			rwMutex.Unlock()
		}()
		wg.Done()
//		fmt.Println(i)
}

*/

	//client := xServerPb.NewCross_ServerClient(connection)
//	for i:=0; i<6; i++ {
//		wg.Add(1)

	r, err := serverGrpc.Client[PaymentNum%10000].CrossPaymentRequest(serverGrpc.ClientContext[PaymentNum%10000], &xServerPb.CrossPaymentMessage{Pn: int64(PaymentNum), ChainTo: serverGrpc.ChainTo, ChainFrom: serverGrpc.ChainFrom, ChainVal: serverGrpc.ChainVal})
	if err != nil {
		log.Println(err)
		return
	}

	if r.GetResult() == true {
		ctx.JSON(http.StatusOK, gin.H{"message":"Cross-Payment" })
		return
	} else {
		ctx.JSON(http.StatusBadRequest, gin.H{"message":"Cross-Payment" })
		return
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


