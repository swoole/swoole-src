/* Generated by re2c 3.1 */
/*
  +----------------------------------------------------------------------+
  | Copyright (c) The PHP Group                                          |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | https://www.php.net/license/3_01.txt                                 |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Matteo Beccati <mbeccati@php.net>                            |
  +----------------------------------------------------------------------+
*/


#include "php.h"
#include "ext/pdo/php_pdo_driver.h"
#include "ext/pdo/pdo_sql_parser.h"

int pdo_pgsql_scanner(pdo_scanner_t *s)
{
	const char *cursor = s->cur;

	s->tok = cursor;
	

	
{
	YYCTYPE yych;
	unsigned int yyaccept = 0;
	if ((YYLIMIT - YYCURSOR) < 2) YYFILL(2);
	yych = *YYCURSOR;
	switch (yych) {
		case 0x00: goto yy1;
		case '"': goto yy4;
		case '$': goto yy6;
		case '\'': goto yy7;
		case '-': goto yy8;
		case '/': goto yy9;
		case ':': goto yy10;
		case '?': goto yy11;
		case 'E':
		case 'e': goto yy13;
		default: goto yy2;
	}
yy1:
	YYCURSOR = YYMARKER;
	switch (yyaccept) {
		case 0: goto yy5;
		case 1: goto yy17;
		case 2: goto yy23;
		default: goto yy35;
	}
yy2:
	++YYCURSOR;
	if (YYLIMIT <= YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
	switch (yych) {
		case 0x00:
		case '"':
		case '$':
		case '\'':
		case '-':
		case '/':
		case ':':
		case '?':
		case 'E':
		case 'e': goto yy3;
		default: goto yy2;
	}
yy3:
	{ RET(PDO_PARSER_TEXT); }
yy4:
	yyaccept = 0;
	yych = *(YYMARKER = ++YYCURSOR);
	if (yych >= 0x01) goto yy15;
yy5:
	{ SKIP_ONE(PDO_PARSER_TEXT); }
yy6:
	yyaccept = 0;
	yych = *(YYMARKER = ++YYCURSOR);
	switch (yych) {
		case 0x00:
		case 0x01:
		case 0x02:
		case 0x03:
		case 0x04:
		case 0x05:
		case 0x06:
		case 0x07:
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case 0x0E:
		case 0x0F:
		case 0x10:
		case 0x11:
		case 0x12:
		case 0x13:
		case 0x14:
		case 0x15:
		case 0x16:
		case 0x17:
		case 0x18:
		case 0x19:
		case 0x1A:
		case 0x1B:
		case 0x1C:
		case 0x1D:
		case 0x1E:
		case 0x1F:
		case ' ':
		case '!':
		case '"':
		case '#':
		case '%':
		case '&':
		case '\'':
		case '(':
		case ')':
		case '*':
		case '+':
		case ',':
		case '-':
		case '.':
		case '/':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case ':':
		case ';':
		case '<':
		case '=':
		case '>':
		case '?':
		case '@':
		case '[':
		case '\\':
		case ']':
		case '^':
		case '`':
		case '{':
		case '|':
		case '}':
		case '~':
		case 0x7F: goto yy5;
		case '$': goto yy18;
		default: goto yy19;
	}
yy7:
	yyaccept = 0;
	yych = *(YYMARKER = ++YYCURSOR);
	if (yych <= 0x00) goto yy5;
	goto yy21;
yy8:
	yych = *++YYCURSOR;
	switch (yych) {
		case '-': goto yy24;
		default: goto yy5;
	}
yy9:
	yych = *++YYCURSOR;
	switch (yych) {
		case '*': goto yy26;
		default: goto yy5;
	}
yy10:
	yych = *++YYCURSOR;
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case '_':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z': goto yy27;
		case ':': goto yy29;
		default: goto yy5;
	}
yy11:
	yych = *++YYCURSOR;
	switch (yych) {
		case '?': goto yy31;
		default: goto yy12;
	}
yy12:
	{ RET(PDO_PARSER_BIND_POS); }
yy13:
	yyaccept = 0;
	yych = *(YYMARKER = ++YYCURSOR);
	switch (yych) {
		case '\'': goto yy32;
		default: goto yy5;
	}
yy14:
	++YYCURSOR;
	if (YYLIMIT <= YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
yy15:
	switch (yych) {
		case 0x00: goto yy1;
		case '"': goto yy16;
		default: goto yy14;
	}
yy16:
	yyaccept = 1;
	YYMARKER = ++YYCURSOR;
	if (YYLIMIT <= YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
	switch (yych) {
		case '"': goto yy14;
		default: goto yy17;
	}
yy17:
	{ RET(PDO_PARSER_TEXT); }
yy18:
	++YYCURSOR;
	{ RET(PDO_PARSER_CUSTOM_QUOTE); }
yy19:
	++YYCURSOR;
	if (YYLIMIT <= YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
	switch (yych) {
		case 0x00:
		case 0x01:
		case 0x02:
		case 0x03:
		case 0x04:
		case 0x05:
		case 0x06:
		case 0x07:
		case 0x08:
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case 0x0E:
		case 0x0F:
		case 0x10:
		case 0x11:
		case 0x12:
		case 0x13:
		case 0x14:
		case 0x15:
		case 0x16:
		case 0x17:
		case 0x18:
		case 0x19:
		case 0x1A:
		case 0x1B:
		case 0x1C:
		case 0x1D:
		case 0x1E:
		case 0x1F:
		case ' ':
		case '!':
		case '"':
		case '#':
		case '%':
		case '&':
		case '\'':
		case '(':
		case ')':
		case '*':
		case '+':
		case ',':
		case '-':
		case '.':
		case '/':
		case ':':
		case ';':
		case '<':
		case '=':
		case '>':
		case '?':
		case '@':
		case '[':
		case '\\':
		case ']':
		case '^':
		case '`':
		case '{':
		case '|':
		case '}':
		case '~':
		case 0x7F: goto yy1;
		case '$': goto yy18;
		default: goto yy19;
	}
yy20:
	++YYCURSOR;
	if (YYLIMIT <= YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
yy21:
	switch (yych) {
		case 0x00: goto yy1;
		case '\'': goto yy22;
		default: goto yy20;
	}
yy22:
	yyaccept = 2;
	YYMARKER = ++YYCURSOR;
	if (YYLIMIT <= YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
	switch (yych) {
		case '\'': goto yy20;
		default: goto yy23;
	}
yy23:
	{ RET(PDO_PARSER_TEXT); }
yy24:
	++YYCURSOR;
	if (YYLIMIT <= YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
	switch (yych) {
		case '\n': goto yy25;
		default: goto yy24;
	}
yy25:
	{ RET(PDO_PARSER_TEXT); }
yy26:
	++YYCURSOR;
	if (YYLIMIT <= YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
	switch (yych) {
		case '*': goto yy33;
		default: goto yy26;
	}
yy27:
	++YYCURSOR;
	if (YYLIMIT <= YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
	switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case '_':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z': goto yy27;
		default: goto yy28;
	}
yy28:
	{ RET(PDO_PARSER_BIND); }
yy29:
	++YYCURSOR;
	if (YYLIMIT <= YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
	switch (yych) {
		case ':': goto yy29;
		default: goto yy30;
	}
yy30:
	{ RET(PDO_PARSER_TEXT); }
yy31:
	++YYCURSOR;
	{ RET(PDO_PARSER_ESCAPED_QUESTION); }
yy32:
	++YYCURSOR;
	if (YYLIMIT <= YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
	switch (yych) {
		case 0x00: goto yy1;
		case '\'': goto yy34;
		case '\\': goto yy36;
		default: goto yy32;
	}
yy33:
	++YYCURSOR;
	if (YYLIMIT <= YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
	switch (yych) {
		case '*': goto yy33;
		case '/': goto yy37;
		default: goto yy26;
	}
yy34:
	yyaccept = 3;
	YYMARKER = ++YYCURSOR;
	if (YYLIMIT <= YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
	switch (yych) {
		case '\'': goto yy32;
		default: goto yy35;
	}
yy35:
	{ RET(PDO_PARSER_TEXT); }
yy36:
	++YYCURSOR;
	if (YYLIMIT <= YYCURSOR) YYFILL(1);
	yych = *YYCURSOR;
	if (yych <= 0x00) goto yy1;
	goto yy32;
yy37:
	++YYCURSOR;
	goto yy25;
}

}
