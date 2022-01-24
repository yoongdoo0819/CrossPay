# CrossPay
블록체인 확장성/상호운용성 연구 프로젝트


## Prerequisites
- Ubuntu : 18.04
- go : 1.15.10
- protoc : libprotoc 3.0.0
- solidity : 0.4.24
- sgx driver : sgx_linux_x64_driver_2.11.100.2
- sgx sdk    : sgx_linux_x64_sdk_2.13.100

## Environment variable

```bash
source ~/sgxsdk/environment   
export GOPATH=~/instapay3.0/instapay   
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$GOPATH/src/github.com/sslab-instapay/instapay-tee-client   
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$GOPATH/src/github.com/sslab-instapay/instapay-tee-x-server   
```

## Execution guideline
### 1. geth    

```bash
data$ ./start.sh
```

### 2. Deploy CrossPay Smart Contract 

```bash
instapay/src/github.com/sslab-instapay/instapay-tee-client/ethereum_test$ go run deploy_contract.go   
```

### 3. Contract Address

```bash
instapay/src/github.com/sslab-instapay/instapay-tee-client/config/ethereum_config.go // contractAddr   
instapay-enclave-client/include/transaction.h // CONTRACT_ADDR
```

### 4. SGX Program

```bash
instapay-enclave-client/apply_new.sh : Client   
instapay-enclave-x-server/apply.sh : Off-chain Server   
```

### 5. Go Applications based on SGX programs

```bash
instapay/src/github.com/sslab-instapay/instapay-tee-client/Alice.sh : Client   
instapay/src/github.com/sslab-instapay/instapay-tee-x-server/start.sh : Off-chain Server      
```
