#pragma once

#include "zend.h"
#include "zend_compile.h"

#if defined(ZEND_VM_FP_GLOBAL_REG) && ((ZEND_VM_KIND == ZEND_VM_KIND_CALL) || (ZEND_VM_KIND == ZEND_VM_KIND_HYBRID))
# define EXECUTE_DATA_D     void
# define EXECUTE_DATA_C
# define EXECUTE_DATA_DC
# define EXECUTE_DATA_CC
# define NO_EXECUTE_DATA_CC
#else
# define EXECUTE_DATA_D     zend_execute_data* execute_data
# define EXECUTE_DATA_C     execute_data
# define EXECUTE_DATA_DC    , EXECUTE_DATA_D
# define EXECUTE_DATA_CC    , EXECUTE_DATA_C
# define NO_EXECUTE_DATA_CC , NULL
#endif

#if defined(ZEND_VM_FP_GLOBAL_REG) && ((ZEND_VM_KIND == ZEND_VM_KIND_CALL) || (ZEND_VM_KIND == ZEND_VM_KIND_HYBRID))
# define OPLINE_D           void
# define OPLINE_C
# define OPLINE_DC
# define OPLINE_CC
#else
# define OPLINE_D           const zend_op* opline
# define OPLINE_C           opline
# define OPLINE_DC          , OPLINE_D
# define OPLINE_CC          , OPLINE_C
#endif

#define FREE_OP(type, var) \
if ((type) & (IS_TMP_VAR|IS_VAR)) { \
zval_ptr_dtor_nogc(EX_VAR(var)); \
}

#define CV_DEF_OF(i) (EX(func)->op_array.vars[i])

#define get_zval_ptr(op_type, node, type) _get_zval_ptr(op_type, node, type EXECUTE_DATA_CC OPLINE_CC)
#define get_zval_ptr_deref(op_type, node, type) _get_zval_ptr_deref(op_type, node, type EXECUTE_DATA_CC OPLINE_CC)
#define get_zval_ptr_undef(op_type, node, type) _get_zval_ptr_undef(op_type, node, type EXECUTE_DATA_CC OPLINE_CC)
#define get_op_data_zval_ptr_r(op_type, node) _get_op_data_zval_ptr_r(op_type, node EXECUTE_DATA_CC OPLINE_CC)
#define get_op_data_zval_ptr_deref_r(op_type, node) _get_op_data_zval_ptr_deref_r(op_type, node EXECUTE_DATA_CC OPLINE_CC)
#define get_zval_ptr_ptr(op_type, node, type) _get_zval_ptr_ptr(op_type, node, type EXECUTE_DATA_CC)
#define get_zval_ptr_ptr_undef(op_type, node, type) _get_zval_ptr_ptr(op_type, node, type EXECUTE_DATA_CC)
#define get_obj_zval_ptr(op_type, node, type) _get_obj_zval_ptr(op_type, node, type EXECUTE_DATA_CC OPLINE_CC)
#define get_obj_zval_ptr_undef(op_type, node, type) _get_obj_zval_ptr_undef(op_type, node, type EXECUTE_DATA_CC OPLINE_CC)
#define get_obj_zval_ptr_ptr(op_type, node, type) _get_obj_zval_ptr_ptr(op_type, node, type EXECUTE_DATA_CC)

static zend_always_inline zval *_get_zval_ptr_tmp(uint32_t var EXECUTE_DATA_DC)
{
    zval *ret = EX_VAR(var);

    ZEND_ASSERT(Z_TYPE_P(ret) != IS_REFERENCE);

    return ret;
}

static zend_always_inline zval *_get_zval_ptr_var(uint32_t var EXECUTE_DATA_DC)
{
    zval *ret = EX_VAR(var);

    return ret;
}

static zend_always_inline zval *_get_zval_ptr_var_deref(uint32_t var EXECUTE_DATA_DC)
{
    zval *ret = EX_VAR(var);

    ZVAL_DEREF(ret);
    return ret;
}

static zend_never_inline ZEND_COLD zval* zval_undefined_cv(uint32_t var EXECUTE_DATA_DC)
{
    if (EXPECTED(EG(exception) == NULL)) {
        zend_string *cv = CV_DEF_OF(EX_VAR_TO_NUM(var));
        zend_error(E_WARNING, "Undefined variable $%s", ZSTR_VAL(cv));
    }
    return &EG(uninitialized_zval);
}

static zend_never_inline ZEND_COLD zval* ZEND_FASTCALL _zval_undefined_op1(EXECUTE_DATA_D)
{
    return zval_undefined_cv(EX(opline)->op1.var EXECUTE_DATA_CC);
}

static zend_never_inline ZEND_COLD zval* ZEND_FASTCALL _zval_undefined_op2(EXECUTE_DATA_D)
{
    return zval_undefined_cv(EX(opline)->op2.var EXECUTE_DATA_CC);
}

#define ZVAL_UNDEFINED_OP1() _zval_undefined_op1(EXECUTE_DATA_C)
#define ZVAL_UNDEFINED_OP2() _zval_undefined_op2(EXECUTE_DATA_C)

static zend_never_inline ZEND_COLD zval *_get_zval_cv_lookup(zval *ptr, uint32_t var, int type EXECUTE_DATA_DC)
{
	switch (type) {
		case BP_VAR_R:
		case BP_VAR_UNSET:
			ptr = zval_undefined_cv(var EXECUTE_DATA_CC);
			break;
		case BP_VAR_IS:
			ptr = &EG(uninitialized_zval);
			break;
		case BP_VAR_RW:
			zval_undefined_cv(var EXECUTE_DATA_CC);
			ZEND_FALLTHROUGH;
		case BP_VAR_W:
			ZVAL_NULL(ptr);
			break;
	}
	return ptr;
}

static zend_always_inline zval *_get_zval_ptr_cv(uint32_t var, int type EXECUTE_DATA_DC)
{
	zval *ret = EX_VAR(var);

	if (UNEXPECTED(Z_TYPE_P(ret) == IS_UNDEF)) {
		if (type == BP_VAR_W) {
			ZVAL_NULL(ret);
		} else {
			return _get_zval_cv_lookup(ret, var, type EXECUTE_DATA_CC);
		}
	}
	return ret;
}

static zend_always_inline zval *_get_zval_ptr_cv_deref(uint32_t var, int type EXECUTE_DATA_DC)
{
	zval *ret = EX_VAR(var);

	if (UNEXPECTED(Z_TYPE_P(ret) == IS_UNDEF)) {
		if (type == BP_VAR_W) {
			ZVAL_NULL(ret);
			return ret;
		} else {
			return _get_zval_cv_lookup(ret, var, type EXECUTE_DATA_CC);
		}
	}
	ZVAL_DEREF(ret);
	return ret;
}

static zend_always_inline zval *_get_zval_ptr_cv_BP_VAR_R(uint32_t var EXECUTE_DATA_DC)
{
	zval *ret = EX_VAR(var);

	if (UNEXPECTED(Z_TYPE_P(ret) == IS_UNDEF)) {
		return zval_undefined_cv(var EXECUTE_DATA_CC);
	}
	return ret;
}

static zend_always_inline zval *_get_zval_ptr_cv_deref_BP_VAR_R(uint32_t var EXECUTE_DATA_DC)
{
	zval *ret = EX_VAR(var);

	if (UNEXPECTED(Z_TYPE_P(ret) == IS_UNDEF)) {
		return zval_undefined_cv(var EXECUTE_DATA_CC);
	}
	ZVAL_DEREF(ret);
	return ret;
}

static zend_always_inline zval *_get_zval_ptr_cv_BP_VAR_IS(uint32_t var EXECUTE_DATA_DC)
{
	zval *ret = EX_VAR(var);

	return ret;
}

static zend_always_inline zval *_get_zval_ptr_cv_BP_VAR_RW(uint32_t var EXECUTE_DATA_DC)
{
	zval *ret = EX_VAR(var);

	if (UNEXPECTED(Z_TYPE_P(ret) == IS_UNDEF)) {
		zval_undefined_cv(var EXECUTE_DATA_CC);
		ZVAL_NULL(ret);
		return ret;
	}
	return ret;
}

static zend_always_inline zval *_get_zval_ptr_cv_BP_VAR_W(uint32_t var EXECUTE_DATA_DC)
{
	zval *ret = EX_VAR(var);

	if (Z_TYPE_P(ret) == IS_UNDEF) {
		ZVAL_NULL(ret);
	}
	return ret;
}

static zend_always_inline zval *_get_zval_ptr(int op_type, znode_op node, int type EXECUTE_DATA_DC OPLINE_DC)
{
	if (op_type & (IS_TMP_VAR|IS_VAR)) {
		if (!ZEND_DEBUG || op_type == IS_VAR) {
			return _get_zval_ptr_var(node.var EXECUTE_DATA_CC);
		} else {
			ZEND_ASSERT(op_type == IS_TMP_VAR);
			return _get_zval_ptr_tmp(node.var EXECUTE_DATA_CC);
		}
	} else {
		if (op_type == IS_CONST) {
			return RT_CONSTANT(opline, node);
		} else if (op_type == IS_CV) {
			return _get_zval_ptr_cv(node.var, type EXECUTE_DATA_CC);
		} else {
			return NULL;
		}
	}
}

static zend_always_inline zval *_get_op_data_zval_ptr_r(int op_type, znode_op node EXECUTE_DATA_DC OPLINE_DC)
{
	if (op_type & (IS_TMP_VAR|IS_VAR)) {
		if (!ZEND_DEBUG || op_type == IS_VAR) {
			return _get_zval_ptr_var(node.var EXECUTE_DATA_CC);
		} else {
			ZEND_ASSERT(op_type == IS_TMP_VAR);
			return _get_zval_ptr_tmp(node.var EXECUTE_DATA_CC);
		}
	} else {
		if (op_type == IS_CONST) {
			return RT_CONSTANT(opline + 1, node);
		} else if (op_type == IS_CV) {
			return _get_zval_ptr_cv_BP_VAR_R(node.var EXECUTE_DATA_CC);
		} else {
			return NULL;
		}
	}
}

static zend_always_inline ZEND_ATTRIBUTE_UNUSED zval *_get_zval_ptr_deref(int op_type, znode_op node, int type EXECUTE_DATA_DC OPLINE_DC)
{
	if (op_type & (IS_TMP_VAR|IS_VAR)) {
		if (op_type == IS_TMP_VAR) {
			return _get_zval_ptr_tmp(node.var EXECUTE_DATA_CC);
		} else {
			ZEND_ASSERT(op_type == IS_VAR);
			return _get_zval_ptr_var_deref(node.var EXECUTE_DATA_CC);
		}
	} else {
		if (op_type == IS_CONST) {
			return RT_CONSTANT(opline, node);
		} else if (op_type == IS_CV) {
			return _get_zval_ptr_cv_deref(node.var, type EXECUTE_DATA_CC);
		} else {
			return NULL;
		}
	}
}

static zend_always_inline ZEND_ATTRIBUTE_UNUSED zval *_get_op_data_zval_ptr_deref_r(int op_type, znode_op node EXECUTE_DATA_DC OPLINE_DC)
{
	if (op_type & (IS_TMP_VAR|IS_VAR)) {
		if (op_type == IS_TMP_VAR) {
			return _get_zval_ptr_tmp(node.var EXECUTE_DATA_CC);
		} else {
			ZEND_ASSERT(op_type == IS_VAR);
			return _get_zval_ptr_var_deref(node.var EXECUTE_DATA_CC);
		}
	} else {
		if (op_type == IS_CONST) {
			return RT_CONSTANT(opline + 1, node);
		} else if (op_type == IS_CV) {
			return _get_zval_ptr_cv_deref_BP_VAR_R(node.var EXECUTE_DATA_CC);
		} else {
			return NULL;
		}
	}
}

static zend_always_inline zval *_get_zval_ptr_undef(int op_type, znode_op node, int type EXECUTE_DATA_DC OPLINE_DC)
{
	if (op_type & (IS_TMP_VAR|IS_VAR)) {
		if (!ZEND_DEBUG || op_type == IS_VAR) {
			return _get_zval_ptr_var(node.var EXECUTE_DATA_CC);
		} else {
			ZEND_ASSERT(op_type == IS_TMP_VAR);
			return _get_zval_ptr_tmp(node.var EXECUTE_DATA_CC);
		}
	} else {
		if (op_type == IS_CONST) {
			return RT_CONSTANT(opline, node);
		} else if (op_type == IS_CV) {
			return EX_VAR(node.var);
		} else {
			return NULL;
		}
	}
}

static zend_always_inline zval *_get_zval_ptr_ptr_var(uint32_t var EXECUTE_DATA_DC)
{
	zval *ret = EX_VAR(var);

	if (EXPECTED(Z_TYPE_P(ret) == IS_INDIRECT)) {
		ret = Z_INDIRECT_P(ret);
	}
	return ret;
}

static inline zval *_get_zval_ptr_ptr(int op_type, znode_op node, int type EXECUTE_DATA_DC)
{
	if (op_type == IS_CV) {
		return _get_zval_ptr_cv(node.var, type EXECUTE_DATA_CC);
	} else /* if (op_type == IS_VAR) */ {
		ZEND_ASSERT(op_type == IS_VAR);
		return _get_zval_ptr_ptr_var(node.var EXECUTE_DATA_CC);
	}
}

static inline ZEND_ATTRIBUTE_UNUSED zval *_get_obj_zval_ptr(int op_type, znode_op op, int type EXECUTE_DATA_DC OPLINE_DC)
{
	if (op_type == IS_UNUSED) {
		return &EX(This);
	}
	return get_zval_ptr(op_type, op, type);
}

static inline ZEND_ATTRIBUTE_UNUSED zval *_get_obj_zval_ptr_undef(int op_type, znode_op op, int type EXECUTE_DATA_DC OPLINE_DC)
{
	if (op_type == IS_UNUSED) {
		return &EX(This);
	}
	return get_zval_ptr_undef(op_type, op, type);
}

static inline ZEND_ATTRIBUTE_UNUSED zval *_get_obj_zval_ptr_ptr(int op_type, znode_op node, int type EXECUTE_DATA_DC)
{
	if (op_type == IS_UNUSED) {
		return &EX(This);
	}
	return get_zval_ptr_ptr(op_type, node, type);
}
