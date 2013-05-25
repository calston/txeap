echo "User-Name=testuser,Password=123456" | radclient 127.0.0.1 auth testseekrit -x
echo "User-Name=test,Password=pass123,EAP-Code=Response,EAP-Id=210,EAP-Type-Identity=test,Message-Authenticator=0x00" | radeapclient -x 127.0.0.1 auth testseekrit
