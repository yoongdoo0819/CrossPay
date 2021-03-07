make clean
make SGX_MODE=SIM

#rm -f ~/instapay3.0/instapay-tee-x-server/enclave.signed.so
#rm -f ~/instapay3.0/instapay-tee-x-server/enclave.so
#rm -f ~/instapay3.0/instapay-tee-x-server/libtee.so
#cp enclave.signed.so ~/instapay3.0/instapay-tee-x-server/enclave.signed.so
#cp enclave.so ~/instapay3.0/instapay-tee-x-server/enclave.so
#cp libtee.so ~/instapay3.0/instapay-tee-x-server/libtee.so

rm -f ~/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server/enclave.signed.so
rm -f ~/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server/enclave.so
rm -f ~/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server/libtee.so
cp enclave.signed.so ~/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server
cp enclave.so ~/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server
cp libtee.so ~/instapay3.0/instapay/src/github.com/sslab-instapay/instapay-tee-x-server
make clean
