package controller

/*
#cgo CPPFLAGS: -I/home/yoongdoo0819/sgxsdk/include -I/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-server
#cgo LDFLAGS: -L/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-server -ltee

#include "app.h"
*/
import "C"

import (
//	"context"
	"net/http"
	"github.com/gin-gonic/gin"
//	"google.golang.org/grpc"
	"sync"
	//"reflect"

//	"github.com/sslab-instapay/instapay-go-server/repository"
	serverPb "github.com/sslab-instapay/instapay-tee-server/proto/server"
	serverGrpc "github.com/sslab-instapay/instapay-tee-server/grpc"
	"log"
	//"time"
	//"fmt"
	"strconv"

//	"github.com/sslab-instapay/instapay-tee-server/config"
)

/*
var connection, err = grpc.Dial(config.EthereumConfig["serverGrpcHost"]+":"+config.EthereumConfig["serverGrpcPort"], grpc.WithInsecure())
var client = serverPb.NewServerClient(connection)
var clientContext, cancel = context.WithTimeout(context.Background(), time.Second*180)
*/

var rwMutex = new(sync.RWMutex)
//var PaymentNum = 1
var tempPaymentNum int

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
	/*
	channelId, err := strconv.Atoi(context.PostForm("channelId"))

	if err != nil{
		log.Println(err)
	}

	channel, err := repository.GetChannelById(channelId)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(channel)
	
	*/
	//myBalance := channel.MyBalance


	context.JSON(http.StatusOK, gin.H{"message": "Channel"})
}

func PaymentToServerChannelHandler(ctx *gin.Context) {

		//otherAddress := context.PostForm("addr")
		//amount, err := strconv.Atoi(context.PostForm("amount"))
		//TODO 주소정보 셋팅
		//address := config.GetAccountConfig(1111)
		//if err != nil {
		//	log.Fatal(err)
		//}

		/*
		rwMutex.Lock()
		tempPaymentNum = serverGrpc.PaymentNum
		serverGrpc.PaymentNum++
		rwMutex.Unlock()
		*/


		myAddress := ctx.PostForm("myAddress")
		otherAddress := ctx.PostForm("otherAddress")
		amount, err := strconv.Atoi(ctx.PostForm("amount"))
		if err != nil {
			log.Println(err)
		}

		rwMutex.Lock()
		var tempPn = serverGrpc.PaymentNum
		serverGrpc.PaymentNum++
		rwMutex.Unlock()

	//	serverGrpc.PaymentRequest[tempPn] = serverGrpc.Payment
		serverGrpc.PaymentRequest[tempPn].Sender = myAddress
		serverGrpc.PaymentRequest[tempPn].MiddleMan = myAddress
		serverGrpc.PaymentRequest[tempPn].Receiver = otherAddress
		serverGrpc.PaymentRequest[tempPn].Amount = int64(amount)
		serverGrpc.PaymentRequest[tempPn].Status = "NONE"

		/*
		connection, err := grpc.Dial(config.EthereumConfig["serverGrpcHost"]+":"+config.EthereumConfig["serverGrpcPort"], grpc.WithInsecure())

		if err != nil {
			log.Println(err)
			ctx.JSON(http.StatusBadRequest, gin.H{"message": err})
			return
		}
		*/
		//
		//defer connection.Close()
		//	client := serverPb.NewServerClient(connection)

		//	clientContext, cancel := context.WithTimeout(context.Background(), time.Second)
		//defer cancel()

			//serverGrpc.StartTime = time.Now()
		/*	r, err := client.PaymentRequest(clientContext, &serverPb.PaymentRequestMessage{From: myAddress, To: otherAddress, Amount: int64(amount)})
		if err != nil {
			log.Println(err)
			ctx.JSON(http.StatusBadRequest, gin.H{"message": err})
			return
		}

		log.Println(r.GetResult())
		*/

		serverGrpc.Client[tempPaymentNum%100].PaymentRequest(serverGrpc.ClientContext[tempPaymentNum%100], &serverPb.PaymentRequestMessage{Pn: int64(tempPn), From: myAddress, To: otherAddress, Amount: int64(amount)})
/*
		fmt.Println(r.GetResult())
		if r.GetResult() == true {
			ctx.JSON(http.StatusOK, gin.H{"message": "Payment"})

		} else {
			ctx.JSON(http.StatusBadRequest, gin.H{"message": "Payment"})

		}
*/
		//	log.Println("tempPaymentNum >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>", tempPaymentNum)
		//log.Println("END", myAddress, otherAddress, amount)
		//	cancel()

		//	elapsedTime := time.Since(serverGrpc.StartTime)
		//	        fmt.Println("****************************************************************")
		//	fmt.Println("execution time : ", elapsedTime.Seconds())	
		//	fmt.Printf("execution time : %s", elapsedTime)

//		ctx.JSON(http.StatusOK, gin.H{"message": "Payment"})

		/*	var data = <- serverGrpc.ChComplete[int(tempPaymentNum)]
		if data == true {
			ctx.JSON(http.StatusOK, gin.H{"message": "Payment"})
		}
		*/
		/*
		if r.GetResult() {
			//log.Println("start", myAddress, otherAddress, amount)
			log.Println("SUCCESS >>>>>>>>>>>>>>>>>>>>>>>>>>", r.GetResult())
			ctx.JSON(http.StatusOK, gin.H{"message": "Payment"})
		} else {
			ctx.JSON(http.StatusBadRequest, gin.H{"message": "Payment"})
		}
		*/

}

func GetChannelListHandler(context *gin.Context){

	/*
	channelList, err := repository.GetChannelList()
	if err != nil {
		log.Fatal(channelList)
	}

	context.JSON(http.StatusOK, gin.H{
		"channels": channelList,
	})
	*/
}


