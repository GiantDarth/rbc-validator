cmake_minimum_required(VERSION 3.10)
project(XKCP C ASM)

set(CMAKE_C_STANDARD 11)

set(XKCP_TARGET "generic64" CACHE STRING "Set TARGET for which kind of feature set to target the build.")
set_property(CACHE XKCP_TARGET PROPERTY STRINGS reference reference32bits compact generic32 generic32lc generic64 generic64lc SSSE3 AVX AVX2 AVX512)

set(COMMON_FILES lib/common/align.h lib/common/brg_endian.h)

# LowLevel.build
set(OPTIMIZED_FILES lib/common/brg_endian.h)
#  Keccak-p[200]
set(K200_REF_FILES ${COMMON_FILES}
        lib/low/KeccakP-200/ref/KeccakP-200-reference.c lib/low/KeccakP-200/ref/KeccakP-200-reference.h
        lib/low/KeccakP-200/ref/KeccakP-200-SnP.h)
set(K200_COMPACT_FILES ${COMMON_FILES} ${OPTIMIZED_FILES} 
        lib/low/KeccakP-200/compact/KeccakP-200-compact.c lib/low/KeccakP-200/compact/KeccakP-200-SnP.h)
set(K200_ARMV6M_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/KeccakP-200/ARM/KeccakP-200-armv6m-le-gcc.s lib/low/KeccakP-200/ARM/KeccakP-200-SnP.h)
set(K200_ARMV7M_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/KeccakP-200/ARM/KeccakP-200-armv7m-le-gcc.s lib/low/KeccakP-200/ARM/KeccakP-200-SnP.h)
set(K200_AVR8 ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/KeccakP-200/AVR8/KeccakP-200-avr8-fast.s lib/low/KeccakP-200/AVR8/KeccakP-200-SnP.h)
#  Keccak-p[400]
set(K400_REF_FILES ${COMMON_FILES}
        lib/low/KeccakP-400/ref/KeccakP-400-reference.c lib/low/KeccakP-400/ref/KeccakP-400-reference.h
        lib/low/KeccakP-400/ref/KeccakP-400-SnP.h)
set(K400_ARMV6M_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/KeccakP-400/ARM/KeccakP-400-armv6m-le-gcc.s lib/low/KeccakP-400/ARM/KeccakP-400-SnP.h)
set(K400_ARMV7M_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/KeccakP-400/ARM/KeccakP-400-armv7m-le-gcc.s lib/low/KeccakP-400/ARM/KeccakP-400-SnP.h)
set(K400_AVR8_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/KeccakP-400/AVR8/KeccakP-400-avr8-fast.s lib/low/KeccakP-400/AVR8/KeccakP-400-SnP.h)
#  Keccak-p[800]
set(K800_REF_FILES ${COMMON_FILES}
        lib/low/KeccakP-800/ref/KeccakP-800-reference.c lib/low/KeccakP-800/ref/KeccakP-800-reference.h
        lib/low/KeccakP-800/ref/KeccakP-800-SnP.h)
set(K800_COMPACT_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/KeccakP-800/compact/KeccakP-800-compact.c lib/low/KeccakP-800/compact/KeccakP-800-SnP.h)
set(K800_PLAIN_FILES ${OPTIMIZED_FILES}
        lib/low/KeccakP-800/plain/KeccakP-800-SnP.h
        lib/low/KeccakP-800/plain/KeccakP-800-opt32-bis.macros
        lib/low/KeccakP-800/plain/KeccakP-800-opt32.c
        lib/low/KeccakP-800/plain/KeccakP-800-opt32.macros
        lib/low/KeccakP-800/plain/KeccakP-800-unrolling-bis.macros
        lib/low/KeccakP-800/plain/KeccakP-800-unrolling.macros)
set(K800_PLAIN_U2_FILES ${K800_PLAIN_FILES} lib/low/KeccakP-800/plain/u2/KeccakP-800-opt32-config.h)
set(K800_PLAIN_UA_FILES ${K800_PLAIN_FILES} lib/low/KeccakP-800/plain/ua/KeccakP-800-opt32-config.h)
set(K800_PLAIN_LCU2_FILES ${K800_PLAIN_FILES} lib/low/KeccakP-800/plain/lcu2/KeccakP-800-opt32-config.h)
set(K800_PLAIN_LCUA_FILES ${K800_PLAIN_FILES} lib/low/KeccakP-800/plain/lcua/KeccakP-800-opt32-config.h)
set(K800_ARM_FILES ${COMMON_FILES} ${OPTIMIZED_FILES} lib/low/KeccakP-800/ARM/KeccakP-800-SnP.h)
set(K800_ARMV6M_U1_FILES ${K800_ARM_FILES} lib/low/KeccakP-800/ARM/KeccakP-800-u1-armv6m-le-gcc.s)
set(K800_ARMV6M_U2_FILES ${K800_ARM_FILES} lib/low/KeccakP-800/ARM/KeccakP-800-u2-armv6m-le-gcc.s)
set(K800_ARMV7M_U2_FILES ${K800_ARM_FILES} lib/low/KeccakP-800/ARM/KeccakP-800-u2-armv7m-le-gcc.s)
set(K800_ARMV7M_UA_FILES ${K800_ARM_FILES} lib/low/KeccakP-800/ARM/KeccakP-800-uf-armv7m-le-gcc.s)
set(K800_ARMV7A_U2_FILES ${K800_ARM_FILES} lib/low/KeccakP-800/ARM/KeccakP-800-u2-armv7a-le-gcc.s)
set(K800_ARMV8A_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/KeccakP-800/ARMv8A/KeccakP-800-armv8a-neon.s lib/low/KeccakP-800/ARMv8A/KeccakP-800-SnP.h)
set(K800_AVR8_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/KeccakP-800/AVR8/KeccakP-800-avr8-fast.s lib/low/KeccakP-800/AVR8/KeccakP-800-SnP.h)
# Keccak-p[1600]
set(K1600_REF_64_BIT_FILES ${COMMON_FILES}
        lib/low/KeccakP-1600/ref-64bits/KeccakP-1600-reference.c
        lib/low/KeccakP-1600/ref-64bits/KeccakP-1600-reference.h
        lib/low/KeccakP-1600/ref-64bits/KeccakP-1600-SnP.h)
set(K1600_REF_32_BIT_FILES ${COMMON_FILES}
        lib/low/KeccakP-1600/ref-32bits/KeccakP-1600-reference32.c
        lib/low/KeccakP-1600/ref-32bits/KeccakP-1600-reference.h
        lib/low/KeccakP-1600/ref-32bits/KeccakP-1600-SnP.h)
set(K1600_COMPACT_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600/compact/KeccakP-1600-compact64.c
        lib/low/KeccakP-1600/compact/KeccakP-1600-SnP.h lib/low/common/SnP-Relaned.h)
set(K1600_AVR8_COMPACT_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600/AVR8/KeccakP-1600-avr8-compact.s
        lib/low/KeccakP-1600/AVR8/KeccakP-1600-SnP.h)
set(K1600_PLAIN_32_BITS_INPLACE_FILES ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600/plain-32bits-inplace/KeccakP-1600-inplace32BI.c
        lib/low/KeccakP-1600/plain-32bits-inplace/KeccakP-1600-SnP.h lib/low/common/SnP-Relaned.h)
set(K1600_ARM_INPLACE_FILES ${OPTIMIZED_FILES} lib/low/KeccakP-1600/ARM/KeccakP-1600-SnP.h)
set(K1600_ARMV6M_INPLACE_FILES ${K1600_ARM_INPLACE_FILES}
        lib/low/KeccakP-1600/ARM/KeccakP-1600-inplace-32bi-armv6m-le-gcc.s)
set(K1600_ARMV7M_INPLACE_FILES ${K1600_ARM_INPLACE_FILES}
        lib/low/KeccakP-1600/ARM/KeccakP-1600-inplace-32bi-armv7m-le-gcc.s)
set(K1600_ARMV7A_INPLACE_FILES ${K1600_ARM_INPLACE_FILES}
        lib/low/KeccakP-1600/ARM/KeccakP-1600-inplace-32bi-armv7a-le-gcc.s)
set(K1600_PLAIN_64_BITS_FILES ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c
        lib/low/KeccakP-1600/common/KeccakP-1600-unrolling.macros
        lib/low/KeccakP-1600/common/KeccakP-1600-64.macros
        lib/low/KeccakP-1600/plain-64bits/KeccakP-1600-SnP.h lib/low/common/SnP-Relaned.h)
set(K1600_PLAIN_64_BITS_U6_FILES ${K1600_PLAIN_64_BITS_FILES}
        lib/low/KeccakP-1600/plain-64bits/u6/KeccakP-1600-opt64-config.h)
set(K1600_PLAIN_64_BITS_UA_FILES ${K1600_PLAIN_64_BITS_FILES}
        lib/low/KeccakP-1600/plain-64bits/ua/KeccakP-1600-opt64-config.h)
set(K1600_PLAIN_64_BITS_LCU6_FILES ${K1600_PLAIN_64_BITS_FILES}
        lib/low/KeccakP-1600/plain-64bits/lcu6/KeccakP-1600-opt64-config.h)
set(K1600_PLAIN_64_BITS_LCUA_FILES ${K1600_PLAIN_64_BITS_FILES}
        lib/low/KeccakP-1600/plain-64bits/lcua/KeccakP-1600-opt64-config.h)
set(K1600_PLAIN_64_BITS_LCUA_SHLD_FILES ${K1600_PLAIN_64_BITS_FILES}
        lib/low/KeccakP-1600/plain-64bits/lcua-shld/KeccakP-1600-opt64-config.h)
set(K1600_X86_64_FILES ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600/x86-64/KeccakP-1600-x86-64-gas.s
        lib/low/KeccakP-1600/x86-64/KeccakP-1600-SnP.h)
set(K1600_X86_64_SHLD_FILES ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600/x86-64/KeccakP-1600-x86-64-shld-gas.s
        lib/low/KeccakP-1600/x86-64/KeccakP-1600-SnP.h)
set(K1600_X86_64_APPLE_FILES ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600/x86-64/KeccakP-1600-x86-64-gas_Apple.s
        lib/low/KeccakP-1600/x86-64/KeccakP-1600-SnP.h)
set(K1600_AVX2_FILES ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600/AVX2/KeccakP-1600-AVX2.s lib/low/KeccakP-1600/AVX2/KeccakP-1600-SnP.h)
set(K1600_AVX512_C_FILES ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600/AVX512/C/KeccakP-1600-AVX512.c
        lib/low/KeccakP-1600/AVX512/C/u12/KeccakP-1600-AVX512-config.h
        lib/low/KeccakP-1600/AVX512/C/KeccakP-1600-SnP.h)
set(K1600_AVX512_FILES ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600/AVX512/KeccakP-1600-AVX512.s lib/low/KeccakP-1600/AVX512/KeccakP-1600-SnP.h)
set(K1600_XOP_FILES ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600/XOP/KeccakP-1600-XOP.c lib/low/KeccakP-1600/XOP/KeccakP-1600-SnP.h
        lib/low/KeccakP-1600/common/KeccakP-1600-unrolling.macros lib/low/common/SnP-Relaned.h)
set(K1600_XOP_U6_FILES ${K1600_XOP_FILES} lib/low/KeccakP-1600/XOP/u6/KeccakP-1600-XOP-config.h)
set(K1600_XOP_UA_FILES ${K1600_XOP_FILES} lib/low/KeccakP-1600/XOP/ua/KeccakP-1600-XOP-config.h)
set(K1600_ARMV6M_FILES ${OPTIMIZED_FILES} lib/low/KeccakP-1600/ARM/KeccakP-1600-SnP.h)
set(K1600_ARMV6M_U1_FILES ${K1600_ARMV6M_FILES}
        lib/low/KeccakP-1600/ARM/KeccakP-1600-u1-32bi-armv6m-le-gcc.s)
set(K1600_ARMV6M_u2_FILES ${K1600_ARMV6M_FILES}
        lib/low/KeccakP-1600/ARM/KeccakP-1600-u2-32bi-armv6m-le-gcc.s)
set(K1600_ARMV7A_NEON_FILES ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600/ARMv7A-NEON/KeccakP-1600-armv7a-le-neon-gcc.s
        lib/low/KeccakP-1600/ARMv7A-NEON/KeccakP-1600-SnP.h)
set(K1600_ARMV8A_FILES ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600/ARMv8A/KeccakP-1600-armv8a-neon.s
        lib/low/KeccakP-1600/ARMv8A/KeccakP-1600-SnP.h)
set(K1600_AVR8_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600/AVR8/KeccakP-1600-avr8-fast.s lib/low/KeccakP-1600/AVR8/KeccakP-1600-SnP.h)
# Keccak-p[1600]×2
set(K1600X2_ON1_FILES
        lib/low/KeccakP-1600-times2/fallback-on1/KeccakP-1600-times2-on1.c
        lib/low/KeccakP-1600-times2/fallback-on1/KeccakP-1600-times2-SnP.h
        lib/low/common/PlSnP-Fallback.inc)
set(K1600X2_SIMD128_FILES ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600-times2/SIMD128/KeccakP-1600-times2-SIMD128.c
        lib/low/KeccakP-1600-times2/SIMD128/KeccakP-1600-times2-SnP.h
        lib/low/KeccakP-1600/common/KeccakP-1600-unrolling.macros)
set(K1600X2_SSSE3_U2_FILES ${K1600X2_SIMD128_FILES}
        lib/low/KeccakP-1600-times2/SIMD128/SSSE3-u2/SIMD128-config.h)
set(K1600X2_SSSE3_UA_FILES ${K1600X2_SIMD128_FILES}
        lib/low/KeccakP-1600-times2/SIMD128/SSSE3-ua/SIMD128-config.h)
set(K1600X2_XOP_U2_FILES ${K1600X2_SIMD128_FILES}
        lib/low/KeccakP-1600-times2/SIMD128/XOP-u2/SIMD128-config.h)
set(K1600X2_XOP_UA_FILES ${K1600X2_SIMD128_FILES}
        lib/low/KeccakP-1600-times2/SIMD128/XOP-ua/SIMD128-config.h)
set(K1600X2_AVX512_FILES ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600-times2/AVX512/KeccakP-1600-times2-SIMD512.c
        lib/low/KeccakP-1600-times2/AVX512/KeccakP-1600-times2-SnP.h)
set(K1600X2_AVX512_U4_FILES ${K1600X2_AVX512_FILES}
        lib/low/KeccakP-1600-times2/AVX512/AVX512u4/SIMD512-2-config.h)
set(K1600X2_AVX512_U12_FILES ${K1600X2_AVX512_FILES}
        lib/low/KeccakP-1600-times2/AVX512/AVX512u12/SIMD512-2-config.h)
set(K1600X2_AVX512_UA_FILES ${K1600X2_AVX512_FILES}
        lib/low/KeccakP-1600-times2/AVX512/AVX512ufull/SIMD512-2-config.h)
set(K1600X2_ARMV7A_NEON_FILES
        lib/low/KeccakP-1600-times2/ARMv7A-NEON/KeccakP-1600-inplace-pl2-armv7a-neon-le-gcc.s
        lib/low/KeccakP-1600-times2/ARMv7A-NEON/KeccakP-1600-times2-SnP.h)
# Keccak-p[1600]×4
set(K1600X4_ON1_FILES lib/low/KeccakP-1600-times4/fallback-on1/KeccakP-1600-times4-on1.c
        lib/low/KeccakP-1600-times4/fallback-on1/KeccakP-1600-times4-SnP.h
        lib/low/common/PlSnP-Fallback.inc)
set(K1600X4_ON2_FILES lib/low/KeccakP-1600-times4/fallback-on2/KeccakP-1600-times4-on2.c
        lib/low/KeccakP-1600-times4/fallback-on2/KeccakP-1600-times4-SnP.h
        lib/low/common/PlSnP-Fallback.inc)
set(K1600X4_AVX2_FILES ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600-times4/AVX2/KeccakP-1600-times4-SIMD256.c
        lib/low/KeccakP-1600-times4/AVX2/KeccakP-1600-times4-SnP.h
        lib/low/KeccakP-1600/common/KeccakP-1600-unrolling.macros)
set(K1600X4_AVX2_U6_FILES ${K1600X4_AVX2_FILES}
        lib/low/KeccakP-1600-times4/AVX2/u6/SIMD256-config.h)
set(K1600X4_AVX2_U12_FILES ${K1600X4_AVX2_FILES}
        lib/low/KeccakP-1600-times4/AVX2/u12/SIMD256-config.h)
set(K1600X4_AVX2_UA_FILES ${K1600X4_AVX2_FILES}
        lib/low/KeccakP-1600-times4/AVX2/ua/SIMD256-config.h)
set(K1600X4_AVX512_FILES ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600-times4/AVX512/KeccakP-1600-times4-SIMD512.c
        lib/low/KeccakP-1600-times4/AVX512/KeccakP-1600-times4-SnP.h)
set(K1600X4_AVX512_U4_FILES ${K1600X4_AVX512_FILES}
        lib/low/KeccakP-1600-times4/AVX512/AVX512u4/SIMD512-4-config.h)
set(K1600X4_AVX512_U12_FILES ${K1600X4_AVX512_FILES}
        lib/low/KeccakP-1600-times4/AVX512/AVX512u12/SIMD512-4-config.h)
set(K1600X4_AVX512_UA_FILES ${K1600X4_AVX512_FILES}
        lib/low/KeccakP-1600-times4/AVX512/AVX512ufull/SIMD512-4-config.h)
# Keccak-p[1600]×8
set(K1600X8_ON1_FILES
        lib/low/KeccakP-1600-times8/fallback-on1/KeccakP-1600-times8-on1.c
        lib/low/KeccakP-1600-times8/fallback-on1/KeccakP-1600-times8-SnP.h
        lib/low/common/PlSnP-Fallback.inc)
set(K1600X8_ON2_FILES
        lib/low/KeccakP-1600-times8/fallback-on2/KeccakP-1600-times8-on2.c
        lib/low/KeccakP-1600-times8/fallback-on2/KeccakP-1600-times8-SnP.h
        lib/low/common/PlSnP-Fallback.inc)
set(K1600X8_ON4_FILES
        lib/low/KeccakP-1600-times8/fallback-on4/KeccakP-1600-times8-on4.c
        lib/low/KeccakP-1600-times8/fallback-on4/KeccakP-1600-times8-SnP.h
        lib/low/common/PlSnP-Fallback.inc)
set(K1600X8_AVX512_FILES ${OPTIMIZED_FILES}
        lib/low/KeccakP-1600-times8/AVX512/KeccakP-1600-times8-SIMD512.c
        lib/low/KeccakP-1600-times8/AVX512/KeccakP-1600-times8-SnP.h)
set(K1600X8_AVX512_U4_FILES ${K1600X8_AVX512_FILES}
        lib/low/KeccakP-1600-times8/AVX512/u4/SIMD512-config.h)
set(K1600X8_AVX512_U12_FILES ${K1600X8_AVX512_FILES}
        lib/low/KeccakP-1600-times8/AVX512/u12/SIMD512-config.h)
set(K1600X8_AVX512_UA_FILES ${K1600X8_AVX512_FILES}
        lib/low/KeccakP-1600-times8/AVX512/ua/SIMD512-config.h)
# Xoodoo
set(XOODOO_FILES lib/low/Xoodoo/Xoodoo.h lib/high/Xoodyak/Xoodyak-parameters.h)
set(XOODOO_REF_FILES ${COMMON_FILES} ${XOODOO_FILES}
        lib/low/Xoodoo/ref/Xoodoo-reference.c lib/low/Xoodoo/ref/Xoodoo-SnP.h)
set(XOODOO_PLAIN_UA_FILES ${COMMON_FILES} ${OPTIMIZED_FILES} ${XOODOO_FILES}
        lib/low/Xoodoo/plain/Xoodoo-optimized.c lib/low/Xoodoo/plain/Xoodyak-full-blocks.c
        lib/low/Xoodoo/plain/Xoodoo-SnP.h)
set(XOODOO_ARMV6_FILES ${COMMON_FILES} ${OPTIMIZED_FILES} ${XOODOO_FILES}
        lib/low/Xoodoo/ARM/Xoodoo-uf-armv6-le-gcc.s lib/low/Xoodoo/ARM/Xoodyak-uf-armv6-le-gcc.s
        lib/low/Xoodoo/ARM/Xoodoo-SnP.h)
set(XOODOO_ARMV6M_FILES ${COMMON_FILES} ${OPTIMIZED_FILES} ${XOODOO_FILES}
        lib/low/Xoodoo/ARM/Xoodoo-u1-armv6m-le-gcc.s lib/low/Xoodoo/ARM/Xoodyak-u1-armv6m-le-gcc.s
        lib/low/Xoodoo/ARM/Xoodoo-SnP.h)
set(XOODOO_ARMV7M_FILES ${COMMON_FILES} ${OPTIMIZED_FILES} ${XOODOO_FILES}
        lib/low/Xoodoo/ARM/Xoodoo-uf-armv7m-le-gcc.s lib/low/Xoodoo/ARM/Xoodyak-uf-armv7m-le-gcc.s
        lib/low/Xoodoo/ARM/Xoodoo-SnP.h)
set(XOODOO_ARMV7A_NEON_FILES ${COMMON_FILES} ${OPTIMIZED_FILES} ${XOODOO_FILES}
        lib/low/Xoodoo/ARMv7A-NEON/Xoodoo-uf-armv7a-neon-le-gcc.s
        lib/low/Xoodoo/ARMv7A-NEON/Xoodyak-uf-armv7a-neon-le-gcc.s
        lib/low/Xoodoo/ARMv7A-NEON/Xoodoo-SnP.h)
set(XOODOO_AVR8_FILES ${COMMON_FILES} ${OPTIMIZED_FILES} ${XOODOO_FILES}
        lib/low/Xoodoo/AVR8/Xoodoo-avr8-u1.s lib/low/Xoodoo/AVR8/Xoodoo-SnP.h)
set(XOODOO_SSE2_FILES ${COMMON_FILES} ${OPTIMIZED_FILES} ${XOODOO_FILES}
        lib/low/Xoodoo/SSE2/Xoodoo-SIMD128.c lib/low/Xoodoo/SSE2/Xoodoo-SnP.h
        lib/low/Xoodoo/SSE2/Xoodyak-full-block-SIMD128.c)
set(XOODOO_AVX512_FILES ${COMMON_FILES} ${OPTIMIZED_FILES} ${XOODOO_FILES}
        lib/low/Xoodoo/AVX512/Xoodoo-SIMD512.c lib/low/Xoodoo/AVX512/Xoodoo-SnP.h
        lib/low/Xoodoo/AVX512/Xoodyak-full-block-SIMD512.c)
# Xoodoo×4
set(XOODOOX4_ON1_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/Xoodoo-times4/fallback-on1/Xoodoo-times4-on1.c
        lib/low/Xoodoo-times4/fallback-on1/Xoodoo-times4-SnP.h
        lib/low/common/PlSnP-Fallback.inc)
set(XOODOOX4_SSSE3_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/Xoodoo-times4/SSSE3/Xoodoo-times4-SIMD128.c
        lib/low/Xoodoo-times4/SSSE3/Xoodoo-times4-SnP.h)
set(XOODOOX4_AVX512_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/Xoodoo-times4/AVX512/Xoodoo-times4-SIMD512.c
        lib/low/Xoodoo-times4/AVX512/Xoodoo-times4-SnP.h)
set(XOODOOX4_ARMV7A_NEON_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/Xoodoo-times4/ARMv7A-NEON/Xoodoo-times4-ARMv7A.s
        lib/low/Xoodoo-times4/ARMv7A-NEON/Xoodoo-times4-SnP.h)
# Xoodoo×8
set(XOODOOX8_ON1_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/Xoodoo-times8/fallback-on1/Xoodoo-times8-on1.c
        lib/low/Xoodoo-times8/fallback-on1/Xoodoo-times8-SnP.h
        lib/low/common/PlSnP-Fallback.inc)
set(XOODOOX8_AVX2_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/Xoodoo-times8/AVX2/Xoodoo-times8-SIMD256.c
        lib/low/Xoodoo-times8/AVX2/Xoodoo-times8-SnP.h)
set(XOODOOX8_AVX512_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/Xoodoo-times8/AVX512/Xoodoo-times8-SIMD512.c
        lib/low/Xoodoo-times8/AVX512/Xoodoo-times8-SnP.h)
# Xoodoo×16
set(XOODOOX16_ON1_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/Xoodoo-times16/fallback-on1/Xoodoo-times16-on1.c
        lib/low/Xoodoo-times16/fallback-on1/Xoodoo-times16-SnP.h
        lib/low/common/PlSnP-Fallback.inc)
set(XOODOOX16_AVX512_FILES ${COMMON_FILES} ${OPTIMIZED_FILES}
        lib/low/Xoodoo-times16/AVX512/Xoodoo-times16-SIMD512.c
        lib/low/Xoodoo-times16/AVX512/Xoodoo-times16-SnP.h)
# Ketje
set(KET_SNP_FILES
        lib/low/Ketje/SnP-compliant/Ket.c lib/low/Ketje/SnP-compliant/Ket.inc
        lib/low/Ketje/SnP-compliant/Ket.h)
set(KET_OPTIMIZED_LE_FILES
        lib/low/Ketje/OptimizedLE/Ket.c lib/low/Ketje/OptimizedLE/Ket.inc
        lib/low/Ketje/OptimizedLE/Ket.h)
set(KET_ARMV7M_FILES
        lib/low/Ketje/OptimizedAsmARM/Ket.h lib/low/Ketje/OptimizedAsmARM/KetjeJr-armv7m-le-gcc.s
        lib/low/Ketje/OptimizedAsmARM/KetjeSr-armv7m-le-gcc.s)

# HighLevel.build
set(KECCAK_SPONGE_FILES ${COMMON_FILES}
        lib/high/Keccak/KeccakSponge.c lib/high/Keccak/KeccakSponge.inc lib/high/Keccak/KeccakSponge.h)
set(FIPS202_FILES ${KECCAK_SPONGE_FILES}
        lib/high/Keccak/FIPS202/SimpleFIPS202.c lib/high/Keccak/FIPS202/SimpleFIPS202.h
        lib/high/Keccak/FIPS202/KeccakHash.c lib/high/Keccak/FIPS202/KeccakHash.h)
set(SP800_185_FILES ${KECCAK_SPONGE_FILES}
        lib/high/Keccak/SP800-185/SP800-185.c lib/high/Keccak/SP800-185/SP800-185.inc
        lib/high/Keccak/SP800-185/SP800-185.h lib/high/common/Phases.h)
set(KECCAK_DUPLEX_FILES ${COMMON_FILES}
        lib/high/Keccak/KeccakDuplex.c lib/high/Keccak/KeccakDuplex.inc lib/high/Keccak/KeccakDuplex.h)
set(KECCAK_PRG_FILES ${KECCAK_DUPLEX_FILES}
        lib/high/Keccak/PRG/KeccakPRG.c lib/high/Keccak/PRG/KeccakPRG.inc
        lib/high/Keccak/PRG/KeccakPRG.h)
set(KETJE_FILES ${COMMON_FILES}
        lib/high/Ketje/Ketjev2.c lib/high/Ketje/Ketjev2.inc lib/high/Ketje/Ketjev2.h)
set(KEYAK_FILES ${COMMON_FILES}
        lib/high/Keyak/Keyakv2.c lib/high/Keyak/Keyakv2.inc lib/high/Keyak/Keyakv2.h
        lib/high/Keyak/Motorist.inc)
set(KANG12_FILES ${KECCAK_SPONGE_FILES}
        lib/high/KangarooTwelve/KangarooTwelve.c lib/high/KangarooTwelve/KangarooTwelve.h
        lib/high/common/Phases.h)
set(KRAVATTE_FILES ${COMMON_FILES}
        lib/high/Kravatte/Kravatte.c lib/high/Kravatte/Kravatte.h
        lib/high/Kravatte/KravatteModes.c lib/high/Kravatte/KravatteModes.h)
set(XOOFFF_FILES ${COMMON_FILES}
        lib/high/Xoofff/Xoofff.c lib/high/Xoofff/Xoofff.h
        lib/high/Xoofff/XoofffModes.c lib/high/Xoofff/XoofffModes.h)
set(XOODYAK_FILES ${COMMON_FILES}
        lib/high/Xoodyak/Xoodyak.c lib/high/Xoodyak/Xoodyak.h
        lib/high/Xoodyak/Cyclist.inc lib/high/Xoodyak/Cyclist.h)
set(ALL_FILES ${ALL_FILES} ${COMMON_FILES} ${KETJE_FILES} ${KEYAK_FILES} ${KECCAK_SPONGE_FILES}
        ${KECCAK_DUPLEX_FILES} ${KECCAK_PRG_FILES} ${FIPS202_FILES} ${SP800_185_FILES} ${KANG12_FILES}
        ${KRAVATTE_FILES} ${XOOFFF_FILES} ${XOODYAK_FILES})

set(UT_FILES ${COMMON_FILES}
        tests/UnitTests/main.c tests/UnitTests/UT.c tests/UnitTests/UT.h tests/UnitTests/testPermutations.c
        tests/UnitTests/testPermutations.h tests/UnitTests/testSnP.inc tests/UnitTests/testPlSnP.inc
        tests/UnitTests/testSponge.c tests/UnitTests/testSponge.inc tests/UnitTests/testSponge.h
        tests/UnitTests/testDuplex.c tests/UnitTests/testDuplex.inc tests/UnitTests/testDuplex.h
        tests/UnitTests/testMotorist.c tests/UnitTests/testMotorist.inc tests/UnitTests/testMotorist.h
        tests/UnitTests/testKeyakv2.c tests/UnitTests/testKeyakv2.inc tests/UnitTests/testKeyakv2.h
        tests/UnitTests/testKetjev2.c tests/UnitTests/testKetjev2.h tests/UnitTests/testKetjev2.inc
        tests/UnitTests/genKAT.c tests/UnitTests/genKAT.h tests/UnitTests/testPRG.c
        tests/UnitTests/testPRG.inc tests/UnitTests/testPRG.h tests/UnitTests/testKangarooTwelve.c
        tests/UnitTests/testKangarooTwelve.h tests/UnitTests/testKravatte.c tests/UnitTests/testKravatte.h
        tests/UnitTests/testKravatteModes.c tests/UnitTests/testKravatteModes.h
        tests/UnitTests/testSP800-185.c tests/UnitTests/testSP800-185.h tests/UnitTests/testXoofff.c
        tests/UnitTests/testXoofff.h tests/UnitTests/testXoofffModes.c tests/UnitTests/testXoofffModes.h
        tests/UnitTests/testXoodyak.c tests/UnitTests/testXoodyak.h
)

# Makefile.build
set(SERIAL_FALLBACK_FILES ${K1600X2_ON1_FILES} ${K1600X4_ON1_FILES} ${K1600X8_ON1_FILES} ${XOODOOX4_ON1_FILES} ${XOODOOX8_ON1_FILES} ${XOODOOX16_ON1_FILES})
set(REFERENCE_FILES ${K200_REF_FILES} ${K400_REF_FILES} ${K800_REF_FILES} ${K1600_REF_64_BIT_FILES} ${SERIAL_FALLBACK_FILES} ${KET_SNP_FILES} ${XOODOO_REF_FILES})
set(REFERENCE_32_BITS_FILES ${K200_REF_FILES} ${K400_REF_FILES} ${K800_REF_FILES} ${K1600_REF_32_BIT_FILES} ${SERIAL_FALLBACK_FILES} ${KET_SNP_FILES} ${XOODOO_REF_FILES})
set(COMPACT_FILES ${K200_COMPACT_FILES} ${K400_REF_FILES} ${K800_COMPACT_FILES} ${K1600_COMPACT_FILES} ${SERIAL_FALLBACK_FILES} ${KET_SNP_FILES} ${XOODOO_PLAIN_UA_FILES})
set(GENERIC32_FILES ${K200_REF_FILES} ${K400_REF_FILES} ${K800_PLAIN_U2_FILES} ${K1600_PLAIN_32_BITS_INPLACE_FILES} ${SERIAL_FALLBACK_FILES} ${KET_SNP_FILES} ${XOODOO_PLAIN_UA_FILES})
set(GENERIC32LC_FILES ${K200_REF_FILES} ${K400_REF_FILES} ${K800_PLAIN_LCU2_FILES} ${K1600_PLAIN_32_BITS_INPLACE_FILES} ${SERIAL_FALLBACK_FILES} ${KET_SNP_FILES} ${XOODOO_PLAIN_UA_FILES})
set(GENERIC64_FILES ${K200_REF_FILES} ${K400_REF_FILES} ${K800_PLAIN_UA_FILES} ${K1600_PLAIN_64_BITS_UA_FILES} ${SERIAL_FALLBACK_FILES} ${KET_SNP_FILES} ${XOODOO_PLAIN_UA_FILES})
set(GENERIC64LC_FILES ${K200_REF_FILES} ${K400_REF_FILES} ${K800_PLAIN_LCUA_FILES} ${K1600_PLAIN_64_BITS_LCUA_FILES} ${SERIAL_FALLBACK_FILES} ${KET_SNP_FILES} ${XOODOO_PLAIN_UA_FILES})
set(SSSE3_FILES ${K200_REF_FILES} ${K400_REF_FILES} ${K800_PLAIN_LCUA_FILES} ${K1600_PLAIN_64_BITS_LCUA_FILES} ${K1600X2_SSSE3_U2_FILES} ${K1600X4_ON2_FILES} ${K1600X8_ON2_FILES} ${KET_SNP_FILES} ${XOODOO_SSE2_FILES} ${XOODOOX4_SSSE3_FILES} ${XOODOOX8_ON1_FILES} ${XOODOOX16_ON1_FILES})
set(AVX_FILES ${K200_REF_FILES} ${K400_REF_FILES} ${K800_PLAIN_LCUA_FILES} ${K1600_PLAIN_64_BITS_LCUA_SHLD_FILES} ${K1600X2_SSSE3_UA_FILES} ${K1600X4_ON2_FILES} ${K1600X8_ON2_FILES} ${KET_SNP_FILES} ${XOODOO_SSE2_FILES} ${XOODOOX4_SSSE3_FILES} ${XOODOOX8_ON1_FILES} ${XOODOOX16_ON1_FILES})
set(XOP_FILES ${K200_REF_FILES} ${K400_REF_FILES} ${K800_PLAIN_LCUA_FILES} ${K1600_XOP_UA_FILES} ${K1600X2_XOP_UA_FILES} ${K1600X4_ON2_FILES} ${K1600X8_ON2_FILES} ${KET_SNP_FILES} ${XOODOO_SSE2_FILES} ${XOODOOX4_SSSE3_FILES} ${XOODOOX8_ON1_FILES} ${XOODOOX16_ON1_FILES})
set(AVX2_FILES ${K200_REF_FILES} ${K400_REF_FILES} ${K800_PLAIN_UA_FILES} ${K1600_AVX2_FILES} ${K1600X2_SSSE3_U2_FILES} ${K1600X4_AVX2_U12_FILES} ${K1600X8_ON4_FILES} ${KET_SNP_FILES} ${XOODOO_SSE2_FILES} ${XOODOOX4_SSSE3_FILES} ${XOODOOX8_AVX2_FILES} ${XOODOOX16_ON1_FILES})
set(AVX2_NO_ASM_FILES ${K200_REF_FILES} ${K400_REF_FILES} ${K800_PLAIN_UA_FILES} ${K1600_PLAIN_64_BITS_UA_FILES} ${K1600X2_SSSE3_U2_FILES} ${K1600X4_AVX2_U12_FILES} ${K1600X8_ON4_FILES} ${KET_SNP_FILES} ${XOODOO_SSE2_FILES} ${XOODOOX4_SSSE3_FILES} ${XOODOOX8_AVX2_FILES} ${XOODOOX16_ON1_FILES})
set(AVX512_FILES ${K200_REF_FILES} ${K400_REF_FILES} ${K800_PLAIN_UA_FILES} ${K1600_AVX512_FILES} ${K1600X2_AVX512_U12_FILES} ${K1600X4_AVX512_U12_FILES} ${K1600X8_AVX512_U12_FILES} ${KET_SNP_FILES} ${XOODOO_AVX512_FILES} ${XOODOOX4_AVX512_FILES} ${XOODOOX8_AVX512_FILES} ${XOODOOX16_AVX512_FILES})

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/config.h
        "#define XKCP_has_Sponge_Keccak\n"
        "#define XKCP_has_FIPS202\n"
        "#define XKCP_has_SP800_185\n"
        "#define XKCP_has_Duplex_Keccak\n"
        "#define XKCP_has_PRG_Keccak\n"
        "#define XKCP_has_Ketje\n"
        "#define XKCP_has_Keyak\n"
        "#define XKCP_has_KangarooTwelve\n"
        "#define XKCP_has_Kravatte\n"
        "#define XKCP_has_Xoofff\n"
        "#define XKCP_has_Xoodyak\n"
        "#define XKCP_has_KeccakP200\n"
        "#define XKCP_has_KeccakP400\n"
        "#define XKCP_has_KeccakP800\n"
        "#define XKCP_has_KeccakP1600\n"
        "#define XKCP_has_KeccakP1600times2\n"
        "#define XKCP_has_KeccakP1600times4\n"
        "#define XKCP_has_KeccakP1600times8\n"
        "#define XKCP_has_Xoodoo\n"
        "#define XKCP_has_Xoodootimes4\n"
        "#define XKCP_has_Xoodootimes8\n"
        "#define XKCP_has_Xoodootimes16\n"
)

if(XKCP_TARGET STREQUAL reference)
        set(ARCH_FILES ${REFERENCE_FILES} ${CMAKE_CURRENT_BINARY_DIR}/config.h ${ALL_FILES})
        list(REMOVE_DUPLICATES ARCH_FILES)
        add_library(XKCP STATIC ${ARCH_FILES})
elseif(XKCP_TARGET STREQUAL reference32bits)
        set(ARCH_FILES ${REFERENCE_32_BITS_FILES} ${CMAKE_CURRENT_BINARY_DIR}/config.h ${ALL_FILES})
        list(REMOVE_DUPLICATES ARCH_FILES)
        add_library(XKCP STATIC ${ARCH_FILES})
elseif(XKCP_TARGET STREQUAL compact)
        set(ARCH_FILES ${COMPACT_FILES} ${CMAKE_CURRENT_BINARY_DIR}/config.h ${ALL_FILES})
        list(REMOVE_DUPLICATES ARCH_FILES)
        add_library(XKCP STATIC ${ARCH_FILES})
elseif(XKCP_TARGET STREQUAL generic32)
        set(ARCH_FILES ${GENERIC32_FILES} ${CMAKE_CURRENT_BINARY_DIR}/config.h ${ALL_FILES})
        list(REMOVE_DUPLICATES ARCH_FILES)
        add_library(XKCP STATIC ${ARCH_FILES})
elseif(XKCP_TARGET STREQUAL generic32lc)
        set(ARCH_FILES ${GENERIC32LC_FILES} ${CMAKE_CURRENT_BINARY_DIR}/config.h ${ALL_FILES})
        list(REMOVE_DUPLICATES ARCH_FILES)
        add_library(XKCP STATIC ${ARCH_FILES})
elseif(XKCP_TARGET STREQUAL generic64)
        set(ARCH_FILES ${GENERIC64_FILES} ${CMAKE_CURRENT_BINARY_DIR}/config.h ${ALL_FILES})
        list(REMOVE_DUPLICATES ARCH_FILES)
        add_library(XKCP STATIC ${ARCH_FILES})
elseif(XKCP_TARGET STREQUAL generic64lc)
        set(ARCH_FILES ${GENERIC64LC_FILES} ${CMAKE_CURRENT_BINARY_DIR}/config.h ${ALL_FILES})
        list(REMOVE_DUPLICATES ARCH_FILES)
        add_library(XKCP STATIC ${ARCH_FILES})
elseif(XKCP_TARGET STREQUAL SSSE3)
        set(ARCH_FILES ${SSSE3_FILES} ${CMAKE_CURRENT_BINARY_DIR}/config.h ${ALL_FILES})
        list(REMOVE_DUPLICATES ARCH_FILES)
        add_library(XKCP STATIC ${ARCH_FILES})
        target_compile_options(XKCP PUBLIC "-msse4.1")
elseif(XKCP_TARGET STREQUAL AVX)
        set(ARCH_FILES ${AVX_FILES} ${CMAKE_CURRENT_BINARY_DIR}/config.h ${ALL_FILES})
        list(REMOVE_DUPLICATES ARCH_FILES)
        add_library(XKCP STATIC ${ARCH_FILES})
        target_compile_options(XKCP PUBLIC "-mavx")
elseif(XKCP_TARGET STREQUAL AVX2)
        set(ARCH_FILES ${AVX2_FILES} ${CMAKE_CURRENT_BINARY_DIR}/config.h ${ALL_FILES})
        list(REMOVE_DUPLICATES ARCH_FILES)
        add_library(XKCP STATIC ${ARCH_FILES})
        target_compile_options(XKCP PUBLIC "-mavx2")
elseif(XKCP_TARGET STREQUAL AVX512)
        set(ARCH_FILES ${AVX512_FILES} ${CMAKE_CURRENT_BINARY_DIR}/config.h ${ALL_FILES})
        list(REMOVE_DUPLICATES ARCH_FILES)
        add_library(XKCP STATIC ${ARCH_FILES})
        target_compile_options(XKCP PUBLIC "-mavx512f" "-mavx512vl" "-mavx512bw")
endif()

# Reset XKCP_INCLUDE_DIRS
set(XKCP_INCLUDE_DIRS "")
foreach(file ${ARCH_FILES})
        string(REGEX REPLACE "^(.*)/.+$" "\\1" dir ${file})
        list(APPEND XKCP_INCLUDE_DIRS ${dir})
endforeach()
list(REMOVE_DUPLICATES XKCP_INCLUDE_DIRS)

target_include_directories(XKCP PUBLIC ${XKCP_INCLUDE_DIRS})

set(HEADER_FILES ${ARCH_FILES})
list(FILTER HEADER_FILES INCLUDE REGEX ".*\.h$")

# Clear out old include
file(REMOVE_RECURSE ${CMAKE_BINARY_DIR}/include/XKCP)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/include/XKCP)
file(COPY ${HEADER_FILES} DESTINATION ${CMAKE_BINARY_DIR}/include/XKCP)

install(TARGETS XKCP ARCHIVE DESTINATION XKCP)
# install(FILES ${HEADER_FILES} TYPE INCLUDE)
