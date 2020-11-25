make clean
make SGX_MODE=SIM
rm -f ~/go/src/github.com/sslab-instapay/instapay-tee-client/enclave.signed.so
rm -f ~/go/src/github.com/sslab-instapay/instapay-tee-client/enclave.so
rm -f ~/go/src/github.com/sslab-instapay/instapay-tee-client/libtee.so
rm -f ~/go/src/github.com/sslab-instapay/instapay-tee-client/data/key/*
cp enclave.signed.so ~/go/src/github.com/sslab-instapay/instapay-tee-client
cp enclave.so ~/go/src/github.com/sslab-instapay/instapay-tee-client
cp libtee.so ~/go/src/github.com/sslab-instapay/instapay-tee-client
make clean
