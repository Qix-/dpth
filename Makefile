.PHONY: all clean

all: dpth
clean:
	rm -rf dpth
dpth: dpth.c
	$(CC) -o $@ $< -Wall -Wextra -Werror -Wunused -std=c99 $(CFLAGS) -lfuse
