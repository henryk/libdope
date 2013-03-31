/*
 ============================================================================
 Name        : exampleProgram.c
 Author      : Henryk Plötz
 Version     :
 Copyright   : (c) 2013 Henryk Plötz
 Description : Uses shared library to print greeting
               To run the resulting executable the LD_LIBRARY_PATH must be
               set to ${project_loc}/libdope/.libs
               Alternatively, libtool creates a wrapper shell script in the
               build directory of this program which can be used to run it.
               Here the script will be called exampleProgram.
 ============================================================================
 */

#include "dope.h"

int main(void) {
	dope_create_master("Foo.conf");
	dope_context_t ctx = dope_init("Foo.conf", NULL, NULL);
	if(ctx == NULL) {
		printf("No context\n");
	} else {
		dope_create_credit(ctx, "Bar.conf", 2);
		dope_create_limited_credit(ctx, "Baz.conf", 3);
		dope_create_debit(ctx, "Quux.conf", 4);
		dope_create_debit(ctx, "Quuux.conf", 5);
		dope_create_debit(ctx, "Quuuux.conf", 6);
		dope_fini(ctx);
	}
	return 0;
}
