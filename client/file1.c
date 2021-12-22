#include <stdio.h>
#include <stdbool.h>

int foo(int x, int y, int z)
{
	y = x + z;
	return y;

}

struct Complex {
    double real;
      double imag;
};


struct Complex AGlobalComplex;


int do_something_with_complex(struct Complex *complex);


void main(){
	
	int a,c;
	int y;

	int x = 0;
	 x = foo(a,y,c);
	// __CPROVER_assume(x<100);
	//__CPROVER_assert(x!=100,"check x");

}
