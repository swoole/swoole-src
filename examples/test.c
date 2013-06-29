#include <stdio.h>

int main(int argc, char **argv)
{
	struct n {
		int a;
		char *b;
		float c;
	} a, b;
	a.a = 123;
	a.b = "hello world";
	a.c = 1234.5;

	b = a;
	printf("a=%d|b=%s|c=%f\n", b.a, b.b, b.c);
	return 0;
}
