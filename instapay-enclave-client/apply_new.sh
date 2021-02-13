make clean
make SGX_MODE=SIM
#rm -f ~/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-client/enclave.signed.so
#rm -f ~/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-client/enclave.so
#rm -f ~/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-client/libtee.so
#rm -f ~/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-client/data/key/*
rm -f ~/instapay3.0/instapay-tee-client/enclave.signed.so
rm -f ~/instapay3.0/instapay-tee-client/enclave.so
rm -f ~/instapay3.0/instapay-tee-client/libtee.so
rm -f ~/instapay3.0/instapay-tee-client/data/key/*
cp enclave.signed.so ~/instapay3.0/instapay-tee-client
cp enclave.so ~/instapay3.0/instapay-tee-client
cp libtee.so ~/instapay3.0/instapay-tee-client
#cp enclave.signed.so ~/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-client/
#cp enclave.so ~/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-client/
#cp libtee.so ~/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-client/
make clean
