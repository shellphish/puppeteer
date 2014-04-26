#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

void doprocessing(int sock)
{
	char buff[1024];
	read(sock, buff, 10000);
	//puts("\n");
	//printf("%08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x");
	//puts("\n");
	//printf(buff);
	//puts("\n");
}

int main( int argc, char *argv[] )
{
	int sockfd, newsockfd, portno, clilen, pid;
	char buffer[256];
	struct sockaddr_in serv_addr, cli_addr;
	int  n;

	/* First call to socket() function */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		perror("ERROR opening socket");
		exit(1);
	}
	/* Initialize socket structure */
	bzero((char *) &serv_addr, sizeof(serv_addr));
	portno = 5001;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);

	/* Now bind the host address using bind() call.*/
	if (bind(sockfd, (struct sockaddr *) &serv_addr,
	         sizeof(serv_addr)) < 0)
	{
		perror("ERROR on binding");
		exit(1);
	}
	/* Now start listening for the clients, here
	 * process will go in sleep mode and will wait
	 * for the incoming connection
	 */
	listen(sockfd, 5);
	clilen = sizeof(cli_addr);
	while (1)
	{
		newsockfd = accept(sockfd,
		                   (struct sockaddr *) &cli_addr, &clilen);
		if (newsockfd < 0)
		{
			perror("ERROR on accept");
			exit(1);
		}
		/* Create child process */
		pid = fork();
		if (pid < 0)
		{
			perror("ERROR on fork");
			exit(1);
		}
		if (pid == 0)
		{
			/* This is the client process */
			close(sockfd);
			doprocessing(newsockfd);
			write(newsockfd, "FINE", 4);
			exit(0);
		}
		else
		{
			close(newsockfd);
		}
	} /* end of while */
}
