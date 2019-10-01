sender: sender.c sender.h header.h
	gcc -o sender sender.c -libverbs -lpthread -lm -ldl
	scp -P 8888 sender kwkwon@147.46.219.151:~/
	scp -P 8888 sender kwkwon@147.46.219.147:~/
	scp -P 8888 sender kwkwon@147.46.219.153:~/
	scp -P 8888 sender kwkwon@147.46.219.228:~/
	scp -P 8888 sender kwkwon@147.46.219.230:~/
	scp -P 8888 sender kwkwon@147.46.215.45:~/
	scp -P 8888 sender kwkwon@147.46.219.240:~/


reciver:
	gcc -o reciever reciever.c -libverbs -lpthread
	scp -P 8888 reciever kwkwon@147.46.219.151:~/
	scp -P 8888 reciever kwkwon@147.46.219.147:~/
	scp -P 8888 reciever kwkwon@147.46.219.153:~/
	scp -P 8888 reciever kwkwon@147.46.219.228:~/
	scp -P 8888 reciever kwkwon@147.46.219.230:~/
	scp -P 8888 reciever kwkwon@147.46.215.45:~/
	scp -P 8888 reciever kwkwon@147.46.219.240:~/

sftp:
	scp -P 8888 sender kwkwon@147.46.219.151:~/
	scp -P 8888 sender kwkwon@147.46.219.153:~/
	scp -P 8888 sender kwkwon@147.46.219.228:~/
	scp -P 8888 sender kwkwon@147.46.219.230:~/
	scp -P 8888 sender kwkwon@147.46.215.45:~/
	scp -P 8888 sender kwkwon@147.46.219.240:~/