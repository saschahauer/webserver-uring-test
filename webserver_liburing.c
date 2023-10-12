/* MIT License

Copyright (c) 2020 Shuveb Hussain

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <liburing.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <getopt.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#define SERVER_STRING           "Server: zerohttpd/0.1\r\n"
#define DEFAULT_SERVER_PORT     8443
#define QUEUE_DEPTH             256
#define READ_SZ                 8192

#define EVENT_TYPE_ACCEPT       0
#define EVENT_TYPE_WRITE        1
#define EVENT_TYPE_SPLICE	2
#define EVENT_TYPE_CLOSE        3

#define MIN_KERNEL_VERSION      5
#define MIN_MAJOR_VERSION       5

struct Endpoint {
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *input;
	BIO *output;
};

struct request {
	struct Endpoint *ep;
	int event_type;
	/* For accept */
	int client_socket;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len;

	/* For splice */
	int fromfd;
	int tofd;
	size_t len;

	/* For close */
	int fd;

	/* For writev */
	int iovec_count;
	struct iovec iov[];
};

static struct io_uring ring;

static const char *unimplemented_content = \
                                "HTTP/1.0 400 Bad Request\r\n"
                                "Content-type: text/html\r\n"
                                "\r\n"
                                "<html>"
                                "<head>"
                                "<title>ZeroHTTPd: Unimplemented</title>"
                                "</head>"
                                "<body>"
                                "<h1>Bad Request (Unimplemented)</h1>"
                                "<p>Your client sent a request ZeroHTTPd did not understand and it is probably not your fault.</p>"
                                "</body>"
                                "</html>";

static const char *http_404_content = \
                                "HTTP/1.0 404 Not Found\r\n"
                                "Content-type: text/html\r\n"
                                "\r\n"
                                "<html>"
                                "<head>"
                                "<title>ZeroHTTPd: Not Found</title>"
                                "</head>"
                                "<body>"
                                "<h1>Not Found (404)</h1>"
                                "<p>Your client is asking for an object that was not found on this server.</p>"
                                "</body>"
                                "</html>";

/*
 One function that prints the system call and the error details
 and then exits with error code 1. Non-zero meaning things didn't go well.
 */
static void fatal_error(const char *syscall) {
	perror(syscall);
	exit(1);
}

static void strtolower(char *str)
{
	for (; *str; ++str)
		*str = (char)tolower(*str);
}

static void *xzalloc(size_t size)
{
	void *buf = calloc(size, 1);

	if (!buf) {
		fprintf(stderr, "Fatal error: unable to allocate memory.\n");
		exit(1);
	}

	return buf;
}

SSL_CTX *ctx;

/*
 * This function is responsible for setting up the main listening socket used by the
 * web server.
 * */
static int setup_listening_socket(int port)
{
	int sock;
	struct sockaddr_in srv_addr;

	OPENSSL_init_ssl(0, NULL);

	ctx = SSL_CTX_new(TLS_method());
	if (!ctx)
		fatal_error("Unable to create SSL context");

	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION |
				SSL_OP_ENABLE_KTLS);
	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
		fatal_error("Unable to get cert.pem");
	if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
		fatal_error("Unable to get key.pem");

	SSL_CTX_set_read_ahead(ctx, 0);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1)
		fatal_error("socket()");

	int enable = 1;
	if (setsockopt(sock,
		       SOL_SOCKET, SO_REUSEADDR,
		       &enable, sizeof(int)) < 0)
		fatal_error("setsockopt(SO_REUSEADDR)");

	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(port);
	srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	/* We bind to a port and turn this socket into a listening
	 * socket.
	 * */
	if (bind(sock, (const struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0)
		fatal_error("bind()");

	if (listen(sock, 10) < 0)
		fatal_error("listen()");

	return sock;
}

static int add_accept_request(int server_socket)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
	struct request *req = xzalloc(sizeof(*req));
	struct Endpoint *ep;

	ep = xzalloc(sizeof(*ep));
	req->ep = ep;
	ep->ctx = ctx;

	ep->ssl = SSL_new(ctx);
	SSL_set_accept_state(ep->ssl);

	ep->input = BIO_new(BIO_s_mem());
	ep->output = BIO_new(BIO_s_mem());
	SSL_set_bio(ep->ssl, ep->input, ep->output);

	req->client_addr_len = sizeof(struct sockaddr_in);

	io_uring_prep_accept(sqe, server_socket, (struct sockaddr *)&req->client_addr,
			     &req->client_addr_len, 0);

	req->event_type = EVENT_TYPE_ACCEPT;
	io_uring_sqe_set_data(sqe, req);

	return 0;
}

static int add_write_request(struct request *req, bool link)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);

	req->event_type = EVENT_TYPE_WRITE;
	io_uring_prep_writev(sqe, req->client_socket, req->iov, req->iovec_count, 0);
	sqe->msg_flags = RWF_DSYNC;

	if (link)
		io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);

	io_uring_sqe_set_data(sqe, req);

	return 0;
}

static void add_close_request(int fd)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
	struct request *req = xzalloc(sizeof(*req));

	req->fd = fd;

	io_uring_prep_close(sqe, fd);
	req->event_type = EVENT_TYPE_CLOSE;
	io_uring_sqe_set_data(sqe, req);
}

static void add_splice_request(int fromfd, int tofd, size_t len)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
	struct request *req;

//	printf("Splice %d->%d len: %d\n", fromfd, tofd, len);

	req = xzalloc(sizeof(*req));
	req->fromfd = fromfd;
	req->tofd = tofd;
	req->len = len;
	req->event_type = EVENT_TYPE_SPLICE;
	io_uring_prep_splice(sqe, fromfd, -1, tofd, -1, len, 0);
	io_uring_sqe_set_data(sqe, req);
}

static void _send_static_string_content(const char *str, int client_socket)
{
	struct request *req = xzalloc(sizeof(*req) + sizeof(struct iovec));
	unsigned long slen = strlen(str);

	req->iovec_count = 1;
	req->client_socket = client_socket;
	req->iov[0].iov_base = xzalloc(slen);
	req->iov[0].iov_len = slen;
	memcpy(req->iov[0].iov_base, str, slen);
	add_write_request(req, false);
}

/*
 * When ZeroHTTPd encounters any other HTTP method other than GET or POST, this function
 * is used to inform the client.
 * */

static void handle_unimplemented_method(int client_socket)
{
	_send_static_string_content(unimplemented_content, client_socket);
}

/*
 * This function is used to send a "HTTP Not Found" code and message to the client in
 * case the file requested is not found.
 * */

static void handle_http_404(int client_socket)
{
	_send_static_string_content(http_404_content, client_socket);
}

/*
 * Sends the HTTP 200 OK header, the server string, for a few types of files, it can also
 * send the content type based on the file extension. It also sends the content length
 * header. Finally it send a '\r\n' in a line by itself signalling the end of headers
 * and the beginning of any content.
 */
static void send_headers(int fd, const char *path, off_t len)
{
	struct iovec *iov;
	struct request *req;
	char small_case_path[1024];
	char send_buffer[1024];

	req = xzalloc(sizeof(*req) + (sizeof(struct iovec) * 4));
	req->iovec_count = 4;
	req->client_socket = fd;

	iov = req->iov;

	strcpy(small_case_path, path);
	strtolower(small_case_path);

	char *str = "HTTP/1.0 200 OK\r\n";
	unsigned long slen = strlen(str);
	iov[0].iov_base = xzalloc(slen);
	iov[0].iov_len = slen;
	memcpy(iov[0].iov_base, str, slen);

	slen = strlen(SERVER_STRING);
	iov[1].iov_base = xzalloc(slen);
	iov[1].iov_len = slen;
	memcpy(iov[1].iov_base, SERVER_STRING, slen);

	/* Send the content-length header, which is the file size in this case. */
	sprintf(send_buffer, "content-length: %jd\r\n", len);
	slen = strlen(send_buffer);
	iov[2].iov_base = xzalloc(slen);
	iov[2].iov_len = slen;
	memcpy(iov[2].iov_base, send_buffer, slen);

	/*
	 * When the browser sees a '\r\n' sequence in a line on its own,
	 * it understands there are no more headers. Content may follow.
	 */
	strcpy(send_buffer, "\r\n");
	slen = strlen(send_buffer);
	iov[3].iov_base = xzalloc(slen);
	iov[3].iov_len = slen;
	memcpy(iov[3].iov_base, send_buffer, slen);

	add_write_request(req, true);
}

static void handle_get_method(char *path, int client_socket)
{
	struct stat path_stat;
	char final_path[1024] = {0};
	int fds[2];
	int fdfile;
	int ret;

	/*
	  If a path ends in a trailing slash, the client probably wants the index
	  file inside of that directory.
	*/
	if (path[strlen(path) - 1] == '/') {
		strcpy(final_path, "public");
		strcat(final_path, path);
		strcat(final_path, "index.html");
	} else {
		strcpy(final_path, "public");
		strcat(final_path, path);
	}

	/* The stat() system call will give you information about the file
	 * like type (regular file, directory, etc), size, etc. */
	if (stat(final_path, &path_stat) == -1) {
		printf("404 Not Found: %s (%s)\n", final_path, path);
		handle_http_404(client_socket);
		return;
	}

	/* Check if this is a normal/regular file and not a directory or something else */
	if (!S_ISREG(path_stat.st_mode)) {
		handle_http_404(client_socket);
		printf("404 Not Found: %s\n", final_path);
		return;
	}

	ret = pipe2(fds, O_NONBLOCK);
	if (ret) {
		perror("pipe");
		exit(1);
	}

	fdfile = open(final_path, O_RDONLY);
	if (fdfile < 0) {
		perror("open");
		exit(1);
	}

	add_splice_request(fdfile, fds[1], path_stat.st_size);

	send_headers(client_socket, final_path, path_stat.st_size);

//	printf("200 %s %lld bytes\n", final_path, path_stat.st_size);

	add_splice_request(fds[0], client_socket, path_stat.st_size);
}

/*
 * This function looks at method used and calls the appropriate handler function.
 * Since we only implement GET and POST methods, it calls handle_unimplemented_method()
 * in case both these don't match. This sends an error to the client.
 * */
static void handle_http_method(char *method_buffer, int client_socket)
{
	char *method, *path, *saveptr;

	method = strtok_r(method_buffer, " ", &saveptr);
	strtolower(method);
	path = strtok_r(NULL, " ", &saveptr);

	if (strcmp(method, "get") == 0) {
//		printf("GET on socket %d\n", client_socket);
		handle_get_method(path, client_socket);
	} else {
		handle_unimplemented_method(client_socket);
	}
}

static int get_line(const char *src, char *dest, int dest_sz)
{
	for (int i = 0; i < dest_sz; i++) {
		dest[i] = src[i];
		if (src[i] == '\r' && src[i+1] == '\n') {
			dest[i] = '\0';
			return 0;
		}
	}
	return 1;
}

static int handle_client_request(SSL *ssl, int client_socket)
{
	char ssl_buffer[4096];
	char http_request[1024];
	int ret;

	/* Get the first line, which will be the request */
	ret = SSL_read(ssl, ssl_buffer, sizeof(ssl_buffer));
	if (ret <= 0) {
		ret = SSL_get_error(ssl, ret);
		printf("SSL_read failed with %d\n", ret);
		return ret;
	}

	if (get_line(ssl_buffer, http_request, sizeof(http_request))) {
		fprintf(stderr, "Malformed request\n");
		exit(1);
	}

	handle_http_method(http_request, client_socket);

	return 0;
}

static void complete_accept_request(struct io_uring_cqe *cqe, int server_socket)
{
	int value = 1;
	int ssl_socket;
	int ret;
	struct request *req = (struct request *)(unsigned long)cqe->user_data;
	struct Endpoint *ep = req->ep;

	ssl_socket = cqe->res;

	SSL_set_fd(ep->ssl, ssl_socket);
	ret = SSL_do_handshake(ep->ssl);
	if (ret != 1) {
		printf("SSL_do_handshake failed: %d\n", ret);
		exit(1);
	}

	setsockopt(ssl_socket, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));

	handle_client_request(ep->ssl, ssl_socket);

	add_accept_request(server_socket);

	free(req);
}

static void complete_splice_request(struct io_uring_cqe *cqe)
{
	struct request *req = (struct request *)(unsigned long)cqe->user_data;
	size_t len;

	if (cqe->res < 0 && cqe->res != -EAGAIN) {
		printf("Splice failed with %d\n", cqe->res);
		goto closefds;
	}

	if (!cqe->res) {
		printf("EOF on %d/%d with remaining %jd\n", req->fromfd, req->tofd, req->len);
		goto closefds;
	}

	len = req->len - cqe->res;
	if (!len)
		goto closefds;

	//printf("Splice %d->%d remaining: %d\n", req->fromfd, req->tofd, len);

	if (len) {
		add_splice_request(req->fromfd, req->tofd, len);
	}

	free(req);

	return;

closefds:
	add_close_request(req->fromfd);
	add_close_request(req->tofd);
	free(req);
}

void complete_write_request(struct io_uring_cqe *cqe)
{
	struct request *req = (struct request *)(unsigned long)cqe->user_data;

//	printf("Write done with %d\n", cqe->res);

	free(req);
}

void complete_close_request(struct io_uring_cqe *cqe)
{
	struct request *req = (struct request *)(unsigned long)cqe->user_data;

//	printf("Close %d done with %d\n", req->fd, cqe->res);

	free(req);
}

void server_loop(int server_socket)
{
	struct io_uring_cqe *cqe;
	struct request *req;
	int ret;

	add_accept_request(server_socket);
	io_uring_submit(&ring);

	while (true) {
		ret = io_uring_wait_cqe(&ring, &cqe);
		req = (struct request *)(unsigned long)cqe->user_data;
		if (ret < 0)
			fatal_error("io_uring_wait_cqe");

		switch (req->event_type) {
		case EVENT_TYPE_ACCEPT:
			complete_accept_request(cqe, server_socket);
			break;
		case EVENT_TYPE_SPLICE:
			complete_splice_request(cqe);
			break;
		case EVENT_TYPE_WRITE:
			complete_write_request(cqe);
			break;
		case EVENT_TYPE_CLOSE:
			complete_close_request(cqe);
			break;
		}

		io_uring_submit(&ring);
		io_uring_cqe_seen(&ring, cqe);
	}
}

static void sigint_handler(int signo)
{
	printf("^C pressed. Shutting down: %d\n", signo);
	io_uring_queue_exit(&ring);
	exit(0);
}

/*
 * This needs CONFIG_CRYPTO_USER_API_AEAD and CONFIG_CRYPTO_CRYPTD to work.
 *
 * After this /proc/crypto should contain:
 *
 * name         : gcm(aes)
 * driver       : cryptd(gcm_base(ctr(aes-generic),ghash-generic))
 * module       : kernel
 * priority     : 150
 */
static int add_cryptd_gcm_aes(void)
{
	int tfmfd;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "aead",
		.salg_name = "cryptd(gcm(aes))",
	};

	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tfmfd == -1) {
		perror("socket");
		exit(1);
	}

	bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa));

	return 0;
}

int main(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "c")) != -1) {
		switch (opt) {
		case 'c':
			add_cryptd_gcm_aes();
			break;
		}
	}

	int server_socket = setup_listening_socket(DEFAULT_SERVER_PORT);

	printf("ZeroHTTPd listening on port: %d\n", DEFAULT_SERVER_PORT);

	signal(SIGINT, sigint_handler);
	io_uring_queue_init(QUEUE_DEPTH, &ring, 0);

	server_loop(server_socket);

	return 0;
}
