#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

struct Complex {
  double real;
  double imag;
};

struct Complex AGlobalComplex;
struct Complex BGlobalComplex;
float a;
int do_something_with_complex(int temp1,int *temp2);
//int do_something_with_complex(struct Complex *complex,int x);

/*
int read_time(int time){
	
	return time+2;
}

int ACK(int time){

	while((time = read_time(time))<60){
		
		if(time == 31)
			  return 1;

	}
	assert(time<60);	//ensure that time is >60 at this point, otherwise the negative ACK is a false positive
	return 0;
}
*/

int foo(int x);

int main(){

	int h,j;
	h=j=0;	
	_CPROVER_assume(h<10);
	_CPROVER_assume(j<10);
	int res = h*j;
	//int x = do_something_with_complex(&AGlobalComplex,x);
	int y = 0;
	//ACK(x);
	//int x = do_something_with_complex(y,&y);
	
	//res = foo(y);


	assert(res<99);
}

