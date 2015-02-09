#ifndef _INT_LIB_H_
#define _INT_LIB_H_

int mytolower(int c) 
{ 
    if (c >= 'A' && c <= 'Z') 
    { 
        return c + 'a' - 'A'; 
    } 
    else 
    { 
        return c; 
    } 
} 

int htoi(const char s[],int start,int len) 
{ 
  int i,j; 
    int n = 0; 
    if (s[0] == '0' && (s[1]=='x' || s[1]=='X')) //判断是否有前导0x或者0X
    { 
        i = 2; 
    } 
    else 
    { 
        i = 0; 
    } 
    i+=start;
    j=0;
    for (; (s[i] >= '0' && s[i] <= '9') 
	   || (s[i] >= 'a' && s[i] <= 'f') || (s[i] >='A' && s[i] <= 'F');++i) 
    {   
        if(j>=len)
	{
	  break;
	}
        if (mytolower(s[i]) > '9') 
        { 
            n = 16 * n + (10 + mytolower(s[i]) - 'a'); 
        } 
        else 
        { 
            n = 16 * n + (mytolower(s[i]) - '0'); 
        } 
	j++;
    } 
    return n; 
} 


#endif

