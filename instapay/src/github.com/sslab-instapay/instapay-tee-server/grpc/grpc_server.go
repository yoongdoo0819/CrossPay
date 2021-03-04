package grpc

/*
#cgo CPPFLAGS: -I/home/yoongdoo0819/sgxsdk/include -I/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-server
#cgo LDFLAGS: -L/home/yoongdoo0819/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-server -ltee

#include "app.h"
*/
import "C"

import (
	"net"
	"log"
	"fmt"
	"time"
	"os"
	"sync"
	"context"
	"strconv"
	"google.golang.org/grpc"
	"github.com/sslab-instapay/instapay-tee-server/repository"
	//"github.com/sslab-instapay/instapay-tee-server/config"
	pbServer "github.com/sslab-instapay/instapay-tee-server/proto/server"
	pbClient "github.com/sslab-instapay/instapay-tee-server/proto/client"
	pbXServer"github.com/sslab-instapay/instapay-tee-server/proto/cross-server"
	"unsafe"
	"reflect"
)

type ServerGrpc struct {
	pbServer.UnimplementedServerServer
}

var rwMutex = new(sync.RWMutex)

func SendAgreementRequest(pn int64, address string, paymentInformation PaymentInformation) {
	
	log.Println("pn : ", pn)
	log.Println("address : ", address)
	//fmt.Println("payment information : ", paymentInformation)
	
	info, err := repository.GetClientInfo(address)
	fmt.Println("client ip   : ", (*info).IP)
	fmt.Println("client port : ", strconv.Itoa((*info).Port))
	if err != nil {
		log.Fatal("GetClientInfo err : ", err)
	}

	clientAddr := (*info).IP + ":" + strconv.Itoa((*info).Port)
	conn, err := grpc.Dial(clientAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatal("conn err : ", err)
	}

	fmt.Println("clientAddr : ", clientAddr)
	defer conn.Close()

	client := pbClient.NewClientClient(conn)
	if client == nil {
		log.Fatal("client conn err")
	}
	fmt.Println("client : ", client)
	
	channelSlice := paymentInformation.ChannelInform
	amountSlice := paymentInformation.AmountInform
	fmt.Println("channelSlice : ", channelSlice)
	fmt.Println("amountSlice  : ", amountSlice)
	fmt.Println("len channelSlice : ", len(channelSlice))

	var originalMessage *C.uchar
	var signature *C.uchar

	fmt.Println("===== CREATE AG REQ MSG START IN ENCLAVE =====")
	C.ecall_create_ag_req_msg_w(C.uint(pn), C.uint(len(channelSlice)), &channelSlice[0], &amountSlice[0], &originalMessage, &signature)
	fmt.Println("===== CREATE AG REQ MSG END IN ENCLAVE =====")
	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)
	
	r, err := client.AgreementRequest(context.Background(), &pbClient.AgreeRequestsMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByte, Signature: signatureByte})
	if err != nil {
		log.Println("client AgreementRequest err : ", err)
	}

	log.Println("r.Result : ", r.Result)
	if r.Result {
		agreementOriginalMessage, agreementSignature := convertByteToPointer(r.OriginalMessage, r.Signature)
		C.ecall_verify_ag_res_msg_w(&([]C.uchar(address)[0]), agreementOriginalMessage, agreementSignature)
	}

	rwMutex.Lock()
	C.ecall_update_sentagr_list_w(C.uint(pn), &([]C.uchar(address)[0]))
	rwMutex.Unlock()

	return
}

func SendUpdateRequest(pn int64, address string, paymentInformation PaymentInformation) {
	info, err := repository.GetClientInfo(address)
	if err != nil {
		log.Fatal(err)
	}

	clientAddr := (*info).IP + ":" + strconv.Itoa((*info).Port)
	conn, err := grpc.Dial(clientAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	client := pbClient.NewClientClient(conn)

	channelSlice := paymentInformation.ChannelInform
	amountSlice := paymentInformation.AmountInform
	var originalMessage *C.uchar
	var signature *C.uchar

	C.ecall_create_ud_req_msg_w(C.uint(pn), C.uint(len(channelSlice)), &channelSlice[0], &amountSlice[0], &originalMessage, &signature)

	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

	rqm := pbClient.UpdateRequestsMessage{ /* convert AgreeRequestsMessage to UpdateRequestsMessage */
		PaymentNumber:   pn,
		OriginalMessage: originalMessageByte,
		Signature:       signatureByte,
	}

	r, err := client.UpdateRequest(context.Background(), &rqm)
	if err != nil {
		log.Fatal(err)
	}

	if r.Result {
		updateOriginalMessage, updateSignature := convertByteToPointer(r.OriginalMessage, r.Signature)
		C.ecall_verify_ud_res_msg_w(&([]C.uchar(address)[0]), updateOriginalMessage, updateSignature)
	}

	rwMutex.Lock()
	C.ecall_update_sentupt_list_w(C.uint(pn), &([]C.uchar(address))[0])
	rwMutex.Unlock()

	return
}

func SendConfirmPayment(pn int, address string) {
	info, err := repository.GetClientInfo(address)
	if err != nil {
		log.Fatal(err)
	}

	clientAddr := (*info).IP + ":" + strconv.Itoa((*info).Port)
	conn, err := grpc.Dial(clientAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	client := pbClient.NewClientClient(conn)

	var originalMessage *C.uchar
	var signature *C.uchar
	C.ecall_create_confirm_msg_w(C.uint(int32(pn)), &originalMessage, &signature)

	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

	_, err = client.ConfirmPayment(context.Background(), &pbClient.ConfirmRequestsMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByte, Signature: signatureByte}, )
	if err != nil {
		log.Println(err)
	}
}

func WrapperAgreementRequest(pn int64, p []string, paymentInformation map[string]PaymentInformation) {
	/* remove C's address from p */
	var q []string
	q = p[0:2]

	for _, address := range q {
		go SendAgreementRequest(pn, address, paymentInformation[address])
	}

	for C.ecall_check_unanimity_w(C.uint(pn), C.int(0)) != 1 {
	}

	fmt.Println("[ALARM] ALL USERS AGREED")
	
	go WrapperUpdateRequest(pn, p, paymentInformation)
}

func WrapperUpdateRequest(pn int64, p []string, paymentInformation map[string]PaymentInformation) {
	for _, address := range p {
		go SendUpdateRequest(pn, address, paymentInformation[address])
	}

	for C.ecall_check_unanimity_w(C.uint(pn), C.int(1)) != 1 {
	}

	fmt.Println("[ALARM] ALL USERS UPDATED")

	go WrapperConfirmPayment(int(pn), p)
}

func WrapperConfirmPayment(pn int, p []string) {
	/* update payment's status */
	C.ecall_update_payment_status_to_success_w(C.uint(pn))

	for _, address := range p {
		go SendConfirmPayment(pn, address)
	}
	fmt.Println("SENT CONFIRMATION TO ALL USERS")
}

func SearchPath(pn int64, amount int64) ([]string, map[string]PaymentInformation) {

	log.Println("===== SearchPath Start =====")
	var p []string

	/* composing p */

	p = append(p, "ed26fa51b429c5c5922bee06184ec058c99a73c1")
	p = append(p, "75c6a898f5b92c15035cf05d344fd5123c4949a2")
	p = append(p, "59d853e0fef578589bd8609afbf1f5e5559a73ac")

	/* composing w */
	var channelInform1, channelInform2, channelInform3 []C.uint
	var amountInform1, amountInform2, amountInform3 []C.int

	channelInform1 = append(channelInform1, C.uint(75))
	channelInform2 = append(channelInform2, C.uint(75))
	channelInform2 = append(channelInform2, C.uint(71))
	channelInform3 = append(channelInform3, C.uint(71))

	amountInform1 = append(amountInform1, C.int(-amount))
	amountInform2 = append(amountInform2, C.int(amount))
	amountInform2 = append(amountInform2, C.int(-amount))
	amountInform3 = append(amountInform3, C.int(amount))

	paymentInform1 := PaymentInformation{ChannelInform: channelInform1, AmountInform: amountInform1}
	paymentInform2 := PaymentInformation{ChannelInform: channelInform2, AmountInform: amountInform2}
	paymentInform3 := PaymentInformation{ChannelInform: channelInform3, AmountInform: amountInform3}

	paymentInformation := make(map[string]PaymentInformation)

	paymentInformation["ed26fa51b429c5c5922bee06184ec058c99a73c1"] = paymentInform1
	paymentInformation["75c6a898f5b92c15035cf05d344fd5123c4949a2"] = paymentInform2
	paymentInformation["59d853e0fef578589bd8609afbf1f5e5559a73ac"] = paymentInform3

	log.Println("===== SearchPath End =====")
	return p, paymentInformation
}

func (s *ServerGrpc) PaymentRequest(ctx context.Context, rq *pbServer.PaymentRequestMessage) (*pbServer.Result, error) {
	
	log.Println("===== Payment Request Start =====")
	from := rq.From
	to := rq.To
	amount := rq.Amount

	sender := []C.uchar(from)
	receiver := []C.uchar(to)

	PaymentNum := C.ecall_accept_request_w(&sender[0], &receiver[0], C.uint(amount))
	p, paymentInformation := SearchPath(int64(PaymentNum), amount)

	for i := 0; i < len(p); i++ {
		C.ecall_add_participant_w(PaymentNum, &([]C.uchar(p[i]))[0])
	}
	C.ecall_update_sentagr_list_w(PaymentNum, &([]C.uchar(p[2]))[0])

	go WrapperAgreementRequest(int64(PaymentNum), p, paymentInformation)

	log.Println("===== Payment Request End =====")
	return &pbServer.Result{Result: true}, nil
}

func (s *ServerGrpc) CommunicationInfoRequest(ctx context.Context, address *pbServer.Address) (*pbServer.CommunicationInfo, error) {
	res, err := repository.GetClientInfo(address.Addr)
	if err != nil {
		log.Fatal(err)
	}

	return &pbServer.CommunicationInfo{IPAddress: res.IP, Port: int64(res.Port)}, nil
}

func StartGrpcServer() {
	grpcPort, err := strconv.Atoi(os.Getenv("grpc_port"))
	if err != nil {
		log.Fatal(err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pbServer.RegisterServerServer(grpcServer, &ServerGrpc{})

	grpcServer.Serve(lis)
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

type PaymentInformation struct {
	ChannelInform []C.uint
	AmountInform  []C.int
}

/*
 *
 *instapay 3.0
 */

func (s *ServerGrpc) CrossPaymentPrepareRequest(ctx context.Context, rq *pbServer.CrossPaymentPrepareReqMessage) (*pbServer.Result, error) {


	log.Println("===== Cross Payment Prepare Start =====")

	from := rq.From
	to := rq.To
	amount := rq.Amount
	PaymentNum := rq.Pn

	sender := []C.uchar(from)
	receiver := []C.uchar(to)

	log.Println("~~~~~~~~~~~~~~~~")
	log.Println("sender : ", sender)
	log.Println("receiver : ", receiver)
	log.Println("amount : ", amount)
	log.Println("pn : ", PaymentNum)


	C.ecall_cross_accept_request_w(&sender[0], &receiver[0], C.uint(amount), C.uint(PaymentNum))
	p, paymentInformation := SearchPath(int64(PaymentNum), amount)

	for i := 0; i < len(p); i++ {
		C.ecall_cross_add_participant_w(C.uint(PaymentNum), &([]C.uchar(p[i]))[0])
	}
	C.ecall_cross_update_sentagr_list_w(C.uint(PaymentNum), &([]C.uchar(p[2]))[0])

	go WrapperCrossAgreementRequest(int64(PaymentNum), p, paymentInformation)

/*
	connectionForXServer, err := grpc.Dial(config.EthereumConfig["Cross-ServerGrpcHost"] + ":" + config.EthereumConfig["Cross-ServerGrpcPort"], grpc.WithInsecure())
	log.Println(config.EthereumConfig["Cross-ServerGrpcHost"] + ":" + config.EthereumConfig["Cross-ServerGrpcPort"])

	if err != nil {
		log.Fatal("conn err : ", err)
	}
	defer connectionForXServer.Close()

	XServer := pbXServer.NewCross_ServerClient(connectionForXServer)
	//XServerContext, cancel := context.WithTimeout(context.Background(), time.Second)
	//defer cancel()

	r, err := XServer.CrossPaymentPrepared(context.Background(), &pbXServer.CrossPaymentPrepareResMessage{Result: "true"})
	if err != nil {
		log.Println("CrossPaymentPrepared Err : ", err)
	}

	log.Println(r.GetResult())
*/
	log.Println("===== Cross Payment Prepare End =====")

	return &pbServer.Result{Result: true}, nil
}
/*
func (s *pbServer) mustEmbedUnimplementedServerServer() (*pbServer.Result, error) {


	log.Println("===== unimplemented server =====")
	return &pbServer.Result{Result: true}, nil
}
*/

func (s *ServerGrpc) CrossPaymentCommitRequest(ctx context.Context, rq *pbServer.CrossPaymentCommitReqMessage) (*pbServer.Result, error) {


	log.Println("===== Cross Payment Commit Start =====")

	//from := rq.From
	//to := rq.To
	pn := rq.Pn
	amount := rq.Amount
	log.Println("pn : ", pn)
	//sender := []C.uchar(from)
	//receiver := []C.uchar(to)

	//PaymentNum := C.ecall_accept_request_w(&sender[0], &receiver[0], C.uint(amount))
	p, paymentInformation := SearchPath(pn, amount)

	go WrapperCrossUpdateRequest(pn, p, paymentInformation)
/*
	for i := 0; i < len(p); i++ {
		C.ecall_add_participant_w(PaymentNum, &([]C.uchar(p[i]))[0])
	}
	C.ecall_update_sentagr_list_w(PaymentNum, &([]C.uchar(p[2]))[0])
*/
	//go WrapperCrossAgreementRequest(int64(PaymentNum), p, paymentInformation)

/*
	connectionForXServer, err := grpc.Dial(config.EthereumConfig["Cross-ServerGrpcHost"] + ":" + config.EthereumConfig["Cross-ServerGrpcPort"], grpc.WithInsecure())
	log.Println(config.EthereumConfig["Cross-ServerGrpcHost"] + ":" + config.EthereumConfig["Cross-ServerGrpcPort"])

	if err != nil {
		log.Fatal("conn err : ", err)
	}
	defer connectionForXServer.Close()

	XServer := pbXServer.NewCross_ServerClient(connectionForXServer)
	//XServerContext, cancel := context.WithTimeout(context.Background(), time.Second)
	//defer cancel()

	r, err := XServer.CrossPaymentCommitted(context.Background(), &pbXServer.CrossPaymentCommitResMessage{Result: true})
	if err != nil {
		log.Println("CrossPaymentCommitted Err : ", err)
	}

	log.Println(r.GetResult())
*/
	log.Println("===== Cross Payment Commit End =====")

	return &pbServer.Result{Result: true}, nil
}

func SendCrossAgreementRequest(pn int64, address string, paymentInformation PaymentInformation) {
	
	log.Println("pn : ", pn)
	log.Println("address : ", address)
	//fmt.Println("payment information : ", paymentInformation)
	
	info, err := repository.GetClientInfo(address)
	fmt.Println("client ip   : ", (*info).IP)
	fmt.Println("client port : ", strconv.Itoa((*info).Port))
	if err != nil {
		log.Fatal("GetClientInfo err : ", err)
	}

	clientAddr := (*info).IP + ":" + strconv.Itoa((*info).Port)
	conn, err := grpc.Dial(clientAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatal("conn err : ", err)
	}

	fmt.Println("clientAddr : ", clientAddr)
	defer conn.Close()

	client := pbClient.NewClientClient(conn)
	if client == nil {
		log.Fatal("client conn err")
	}
	fmt.Println("client : ", client)
	
	channelSlice := paymentInformation.ChannelInform
	amountSlice := paymentInformation.AmountInform
	fmt.Println("channelSlice : ", channelSlice)
	fmt.Println("amountSlice  : ", amountSlice)
	fmt.Println("len channelSlice : ", len(channelSlice))

	var originalMessage *C.uchar
	var signature *C.uchar

	fmt.Println("===== CREATE AG REQ MSG START IN ENCLAVE =====")
	C.ecall_cross_create_ag_req_msg_w(C.uint(pn), C.uint(len(channelSlice)), &channelSlice[0], &amountSlice[0], &originalMessage, &signature)
	fmt.Println("===== CREATE AG REQ MSG END IN ENCLAVE =====")
	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

	r, err := client.AgreementRequest(context.Background(), &pbClient.AgreeRequestsMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByte, Signature: signatureByte})
	if err != nil {
		log.Println("client AgreementRequest err : ", err)
	}

	log.Println("r.Result : ", r.Result)
	if r.Result {
		agreementOriginalMessage, agreementSignature := convertByteToPointer(r.OriginalMessage, r.Signature)
		is_verified := C.ecall_cross_verify_ag_res_msg_w(&([]C.uchar(address)[0]), agreementOriginalMessage, agreementSignature)
		log.Println("is_verified : ", is_verified)

	}

	rwMutex.Lock()
	C.ecall_cross_update_sentagr_list_w(C.uint(pn), &([]C.uchar(address)[0]))
	rwMutex.Unlock()

	return
}

func SendCrossUpdateRequest(pn int64, address string, paymentInformation PaymentInformation) {
	info, err := repository.GetClientInfo(address)
	if err != nil {
		log.Fatal(err)
	}

	clientAddr := (*info).IP + ":" + strconv.Itoa((*info).Port)
	log.Println("CrossUpdate Client : ", clientAddr)

	conn, err := grpc.Dial(clientAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	client := pbClient.NewClientClient(conn)

	channelSlice := paymentInformation.ChannelInform
	amountSlice := paymentInformation.AmountInform
	var originalMessage *C.uchar
	var signature *C.uchar

	log.Println("===== SendCrossUpdateRequest =====")
	C.ecall_cross_create_ud_req_msg_w(C.uint(pn), C.uint(len(channelSlice)), &channelSlice[0], &amountSlice[0], &originalMessage, &signature)

	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

	rqm := pbClient.UpdateRequestsMessage{ /* convert AgreeRequestsMessage to UpdateRequestsMessage */
		PaymentNumber:   pn,
		OriginalMessage: originalMessageByte,
		Signature:       signatureByte,
	}

	r, err := client.UpdateRequest(context.Background(), &rqm)
	if err != nil {
		log.Fatal(err)
	}

	if r.Result {
		updateOriginalMessage, updateSignature := convertByteToPointer(r.OriginalMessage, r.Signature)
		C.ecall_cross_verify_ud_res_msg_w(&([]C.uchar(address)[0]), updateOriginalMessage, updateSignature)
	}

	log.Println("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
	rwMutex.Lock()
	C.ecall_cross_update_sentupt_list_w(C.uint(pn), &([]C.uchar(address))[0])
	rwMutex.Unlock()

	return
}

func SendCrossConfirmPayment(pn int, address string) {
	info, err := repository.GetClientInfo(address)
	if err != nil {
		log.Fatal(err)
	}

	clientAddr := (*info).IP + ":" + strconv.Itoa((*info).Port)
	conn, err := grpc.Dial(clientAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	client := pbClient.NewClientClient(conn)

	var originalMessage *C.uchar
	var signature *C.uchar
	C.ecall_cross_create_confirm_msg_w(C.uint(int32(pn)), &originalMessage, &signature)

	originalMessageByte, signatureByte := convertPointerToByte(originalMessage, signature)

	_, err = client.ConfirmPayment(context.Background(), &pbClient.ConfirmRequestsMessage{PaymentNumber: int64(pn), OriginalMessage: originalMessageByte, Signature: signatureByte}, )
	if err != nil {
		log.Println(err)
	}
}

func WrapperCrossAgreementRequest(pn int64, p []string, paymentInformation map[string]PaymentInformation) {
	/* remove C's address from p */
	var q []string
	q = p[0:2]

	for _, address := range q {
		go SendCrossAgreementRequest(pn, address, paymentInformation[address])
	}

	for C.ecall_cross_check_unanimity_w(C.uint(pn), C.int(0)) != 1 {
	}

	fmt.Println("[ALARM] ALL USERS AGREED")

	connectionForXServer, err := grpc.Dial("141.223.121.164:50009", grpc.WithInsecure())
	if err != nil {
		log.Fatal("conn err : ", err)
	}
	defer connectionForXServer.Close()

	XServer := pbXServer.NewCross_ServerClient(connectionForXServer)
	XServerContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r, err := XServer.CrossPaymentPrepared(XServerContext, &pbXServer.CrossPaymentPrepareResMessage{Pn: pn, Result: true})
	if err != nil {
		return
	}

	log.Println(r.GetResult())
	//go WrapperCrossUpdateRequest(pn, p, paymentInformation)
}

func WrapperCrossUpdateRequest(pn int64, p []string, paymentInformation map[string]PaymentInformation) {
	for _, address := range p {
		go SendCrossUpdateRequest(pn, address, paymentInformation[address])
	}

	fmt.Println("pn : ", pn)
	for C.ecall_cross_check_unanimity_w(C.uint(pn), C.int(1)) != 1 {
	}

	fmt.Println("[ALARM] ALL USERS UPDATED")

	go WrapperCrossConfirmPayment(int(pn), p)
}

func WrapperCrossConfirmPayment(pn int, p []string) {
	/* update payment's status */
	C.ecall_cross_update_payment_status_to_success_w(C.uint(pn))

	for _, address := range p {
		go SendCrossConfirmPayment(pn, address)
	}
	fmt.Println("SENT CONFIRMATION TO ALL USERS")
}


