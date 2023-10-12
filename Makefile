all:
	gcc http_downloader.c -o http_downloader -lssl -lcrypto -lpthread
