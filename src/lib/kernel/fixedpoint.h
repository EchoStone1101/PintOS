#ifndef __LIB_KERNEL_FIXEDPOINT_H
#define __LIB_KERNEL_FIXEDPOINT_H

#include <inttypes.h>

/** Integer simulated fixed-point real arithmetics, implemented by
    macros.
    
    Provides a type for [p].[q] fixed-point real number, and basic
    arithmetics. Here, [p].[q] indicates that a 32-bit integer is
    to be interpreted as

        [ sign bit ][ integer bits ].[ fractal bits ]
       ^           ^               ^                ^
       32          31              q                0
		
		with p bits as integer bits and q bits as fractal bits, where p+q
		= 31. They are defaulted to be 17:14. */


/** Representation configurations */
#define FP_FRAC 14
#define FP_INT (31-FP_FRAC)
#define FP_F (1<<FP_FRAC)

/** Fixed point type */
typedef int32_t fp_real;

/** Type conversion */
#define fp_to_real(N) ((N)*FP_F)
#define fp_to_int_zero(X) ((X)/FP_F)
#define fp_to_int_nearest(X) ((X)>=0 ? (((X)+FP_F/2)/FP_F) : \
																			 (((X)-FP_F/2)/FP_F))

/** Arithmetics */
#define fp_add(X,Y) ((X)+(Y))
#define fp_add_int(X,N) ((X) + fp_to_real(N))
#define fp_sub(X,Y) ((X)-(Y))
#define fp_sub_int(X,N) ((X) - fp_to_real(N))
#define fp_mult(X,Y) ( ((int64_t)(X)) * (Y) / FP_F )
#define fp_mult_int(X,N) ((X)*(N))
#define fp_div(X,Y) ( ((int64_t)(X)) * FP_F / (Y) )
#define fp_div_int(X,N) ((X)/(N))


#endif /**< lib/kernel/fixedpoint.h */