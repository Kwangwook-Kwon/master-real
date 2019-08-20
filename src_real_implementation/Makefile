sender: sender.c sender.h header.h
	gcc -o sender sender.c -libverbs -lpthread

reciver:
	gcc -o reciever reciever.c -libverbs -lpthread

sftp:
	scp -P 8888 reciever kwkwon@147.46.219.147:~/