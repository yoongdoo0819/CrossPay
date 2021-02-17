package main

/*
#cgo CPPFLAGS: -I/home/xiaofo/sgxsdk/include -I./untrusted -I./include
#cgo LDFLAGS: -L. -ltee

#include "untrusted/app.h"
*/
import "C"

import (
	"fmt"
)

func main() {
	C.initialize_enclave()

	A := []C.uchar("78902c58006916201F65f52f7834e467877f0500")
	owner := []C.uchar("D03A2CC08755eC7D75887f0997195654b928893e")
	B := []C.uchar("0b4161ad4f49781a821c308d672e6c669139843c")

	PaymentNum := C.ecall_accept_request_w(&A[0], &B[0], C.uint(8))
	fmt.Printf("payment number: %d\n", PaymentNum)

	C.ecall_add_participant_w(PaymentNum, &A[0]);
	C.ecall_add_participant_w(PaymentNum, &owner[0]);
	C.ecall_add_participant_w(PaymentNum, &B[0]);

	C.ecall_update_sentagr_list_w(PaymentNum, &A[0]);
	C.ecall_update_sentagr_list_w(PaymentNum, &owner[0]);
	//C.ecall_update_sentagr_list_w(PaymentNum, &B[0]);

    Flag := C.ecall_check_unanimity_w(PaymentNum, C.int(0));
    fmt.Println(Flag)
}
