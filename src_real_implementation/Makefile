sender: sender.c sender.h header.h
	gcc -o sender sender.c -libverbs -lpthread
	scp -P 8888 sender kwkwon@147.46.219.151:~/

reciver:
	gcc -o reciever reciever.c -libverbs -lpthread
	scp -P 8888 reciever kwkwon@147.46.219.147:~/
