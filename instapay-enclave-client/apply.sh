make clean
make
rm -f ~/instapay/src/github.com/sslab-instapay/instapay-tee-client/enclave.signed.so
rm -f ~/instapay/src/github.com/sslab-instapay/instapay-tee-client/enclave.so
rm -f ~/instapay/src/github.com/sslab-instapay/instapay-tee-client/libtee.so
cp enclave.signed.so ~/instapay/src/github.com/sslab-instapay/instapay-tee-client
cp enclave.so ~/instapay/src/github.com/sslab-instapay/instapay-tee-client
cp libtee.so ~/instapay/src/github.com/sslab-instapay/instapay-tee-client
make clean