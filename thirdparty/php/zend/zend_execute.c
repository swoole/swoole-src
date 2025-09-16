
#include "zend.h"
#include "zend_compile.h"

#if defined(ZEND_VM_FP_GLOBAL_REG) && ((ZEND_VM_KIND == ZEND_VM_KIND_CALL) || (ZEND_VM_KIND == ZEND_VM_KIND_HYBRID))
#define EXECUTE_DATA_D void
#define EXECUTE_DATA_C
#define EXECUTE_DATA_DC
#define EXECUTE_DATA_CC
#define NO_EXECUTE_DATA_CC
#else
#define EXECUTE_DATA_D zend_execute_data *execute_data
#define EXECUTE_DATA_C execute_data
#define EXECUTE_DATA_DC , EXECUTE_DATA_D
#define EXECUTE_DATA_CC , EXECUTE_DATA_C
#define NO_EXECUTE_DATA_CC , NULL
#endif

#if defined(ZEND_VM_FP_GLOBAL_REG) && ((ZEND_VM_KIND == ZEND_VM_KIND_CALL) || (ZEND_VM_KIND == ZEND_VM_KIND_HYBRID))
#define OPLINE_D void
#define OPLINE_C
#define OPLINE_DC
#define OPLINE_CC
#else
#define OPLINE_D const zend_op *opline
#define OPLINE_C opline
#define OPLINE_DC , OPLINE_D
#define OPLINE_CC , OPLINE_C
#endif

#define FREE_OP(type, var)                                                                                             \
    if ((type) & (IS_TMP_VAR | IS_VAR)) {                                                                              \
        zval_ptr_dtor_nogc(EX_VAR(var));                                                                               \
    }

#define RETURN_VALUE_USED(opline) ((opline)->result_type != IS_UNUSED)

#define CV_DEF_OF(i) (EX(func)->op_array.vars[i])

#define get_zval_ptr(op_type, node, type) _get_zval_ptr(op_type, node, type EXECUTE_DATA_CC OPLINE_CC)
#define get_zval_ptr_deref(op_type, node, type) _get_zval_ptr_deref(op_type, node, type EXECUTE_DATA_CC OPLINE_CC)
#define get_zval_ptr_undef(op_type, node, type) _get_zval_ptr_undef(op_type, node, type EXECUTE_DATA_CC OPLINE_CC)
#define get_op_data_zval_ptr_r(op_type, node) _get_op_data_zval_ptr_r(op_type, node EXECUTE_DATA_CC OPLINE_CC)
#define get_op_data_zval_ptr_deref_r(op_type, node)                                                                    \
    _get_op_data_zval_ptr_deref_r(op_type, node EXECUTE_DATA_CC OPLINE_CC)
#define get_zval_ptr_ptr(op_type, node, type) _get_zval_ptr_ptr(op_type, node, type EXECUTE_DATA_CC)
#define get_zval_ptr_ptr_undef(op_type, node, type) _get_zval_ptr_ptr(op_type, node, type EXECUTE_DATA_CC)
#define get_obj_zval_ptr(op_type, node, type) _get_obj_zval_ptr(op_type, node, type EXECUTE_DATA_CC OPLINE_CC)
#define get_obj_zval_ptr_undef(op_type, node, type)                                                                    \
    _get_obj_zval_ptr_undef(op_type, node, type EXECUTE_DATA_CC OPLINE_CC)
#define get_obj_zval_ptr_ptr(op_type, node, type) _get_obj_zval_ptr_ptr(op_type, node, type EXECUTE_DATA_CC)

#if PHP_VERSION_ID < 80300
static ZEND_COLD void zend_illegal_container_offset(zend_string *container, const zval *offset, int type) {
    switch (type) {
    case BP_VAR_IS:
        zend_type_error("Cannot access offset of type %s in isset or empty",
                zend_zval_type_name(offset));
        return;
    case BP_VAR_UNSET:
        /* Consistent error for when trying to unset a string offset */
        if (zend_string_equals(container, ZSTR_KNOWN(ZEND_STR_STRING))) {
            zend_throw_error(NULL, "Cannot unset string offsets");
        } else {
            zend_type_error("Cannot unset offset of type %s on %s", zend_zval_type_name(offset), ZSTR_VAL(container));
        }
        return;
    default:
        zend_type_error("Cannot access offset of type %s on %s",
                zend_zval_type_name(offset), ZSTR_VAL(container));
        return;
    }
}
#endif

static zend_always_inline zval *_get_zval_ptr_tmp(uint32_t var EXECUTE_DATA_DC) {
    zval *ret = EX_VAR(var);

    ZEND_ASSERT(Z_TYPE_P(ret) != IS_REFERENCE);

    return ret;
}

static zend_always_inline zval *_get_zval_ptr_var(uint32_t var EXECUTE_DATA_DC) {
    zval *ret = EX_VAR(var);

    return ret;
}

static zend_always_inline zval *_get_zval_ptr_var_deref(uint32_t var EXECUTE_DATA_DC) {
    zval *ret = EX_VAR(var);

    ZVAL_DEREF(ret);
    return ret;
}

static zend_never_inline ZEND_COLD zval *zval_undefined_cv(uint32_t var EXECUTE_DATA_DC) {
    if (EXPECTED(EG(exception) == NULL)) {
        zend_string *cv = CV_DEF_OF(EX_VAR_TO_NUM(var));
        zend_error(E_WARNING, "Undefined variable $%s", ZSTR_VAL(cv));
    }
    return &EG(uninitialized_zval);
}

static zend_never_inline ZEND_COLD zval *ZEND_FASTCALL _zval_undefined_op1(EXECUTE_DATA_D) {
    return zval_undefined_cv(EX(opline)->op1.var EXECUTE_DATA_CC);
}

static zend_never_inline ZEND_COLD zval *ZEND_FASTCALL _zval_undefined_op2(EXECUTE_DATA_D) {
    return zval_undefined_cv(EX(opline)->op2.var EXECUTE_DATA_CC);
}

#define ZVAL_UNDEFINED_OP1() _zval_undefined_op1(EXECUTE_DATA_C)
#define ZVAL_UNDEFINED_OP2() _zval_undefined_op2(EXECUTE_DATA_C)

static zend_never_inline ZEND_COLD zval *_get_zval_cv_lookup(zval *ptr, uint32_t var, int type EXECUTE_DATA_DC) {
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

static zend_always_inline zval *_get_zval_ptr_cv(uint32_t var, int type EXECUTE_DATA_DC) {
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

static zend_always_inline zval *_get_zval_ptr_cv_deref(uint32_t var, int type EXECUTE_DATA_DC) {
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

static zend_always_inline zval *_get_zval_ptr_cv_BP_VAR_R(uint32_t var EXECUTE_DATA_DC) {
    zval *ret = EX_VAR(var);

    if (UNEXPECTED(Z_TYPE_P(ret) == IS_UNDEF)) {
        return zval_undefined_cv(var EXECUTE_DATA_CC);
    }
    return ret;
}

static zend_always_inline zval *_get_zval_ptr_cv_deref_BP_VAR_R(uint32_t var EXECUTE_DATA_DC) {
    zval *ret = EX_VAR(var);

    if (UNEXPECTED(Z_TYPE_P(ret) == IS_UNDEF)) {
        return zval_undefined_cv(var EXECUTE_DATA_CC);
    }
    ZVAL_DEREF(ret);
    return ret;
}

static zend_always_inline zval *_get_zval_ptr_cv_BP_VAR_IS(uint32_t var EXECUTE_DATA_DC) {
    zval *ret = EX_VAR(var);

    return ret;
}

static zend_always_inline zval *_get_zval_ptr_cv_BP_VAR_RW(uint32_t var EXECUTE_DATA_DC) {
    zval *ret = EX_VAR(var);

    if (UNEXPECTED(Z_TYPE_P(ret) == IS_UNDEF)) {
        zval_undefined_cv(var EXECUTE_DATA_CC);
        ZVAL_NULL(ret);
        return ret;
    }
    return ret;
}

static zend_always_inline zval *_get_zval_ptr_cv_BP_VAR_W(uint32_t var EXECUTE_DATA_DC) {
    zval *ret = EX_VAR(var);

    if (Z_TYPE_P(ret) == IS_UNDEF) {
        ZVAL_NULL(ret);
    }
    return ret;
}

static zend_always_inline zval *_get_zval_ptr(int op_type, znode_op node, int type EXECUTE_DATA_DC OPLINE_DC) {
    if (op_type & (IS_TMP_VAR | IS_VAR)) {
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

static zend_always_inline zval *_get_op_data_zval_ptr_r(int op_type, znode_op node EXECUTE_DATA_DC OPLINE_DC) {
    if (op_type & (IS_TMP_VAR | IS_VAR)) {
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

static zend_always_inline ZEND_ATTRIBUTE_UNUSED zval *_get_zval_ptr_deref(int op_type,
                                                                          znode_op node,
                                                                          int type EXECUTE_DATA_DC OPLINE_DC) {
    if (op_type & (IS_TMP_VAR | IS_VAR)) {
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

static zend_always_inline ZEND_ATTRIBUTE_UNUSED zval *_get_op_data_zval_ptr_deref_r(
    int op_type, znode_op node EXECUTE_DATA_DC OPLINE_DC) {
    if (op_type & (IS_TMP_VAR | IS_VAR)) {
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

static zend_always_inline zval *_get_zval_ptr_undef(int op_type, znode_op node, int type EXECUTE_DATA_DC OPLINE_DC) {
    if (op_type & (IS_TMP_VAR | IS_VAR)) {
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

static zend_always_inline zval *_get_zval_ptr_ptr_var(uint32_t var EXECUTE_DATA_DC) {
    zval *ret = EX_VAR(var);

    if (EXPECTED(Z_TYPE_P(ret) == IS_INDIRECT)) {
        ret = Z_INDIRECT_P(ret);
    }
    return ret;
}

static inline zval *_get_zval_ptr_ptr(int op_type, znode_op node, int type EXECUTE_DATA_DC) {
    if (op_type == IS_CV) {
        return _get_zval_ptr_cv(node.var, type EXECUTE_DATA_CC);
    } else /* if (op_type == IS_VAR) */ {
        ZEND_ASSERT(op_type == IS_VAR);
        return _get_zval_ptr_ptr_var(node.var EXECUTE_DATA_CC);
    }
}

static inline ZEND_ATTRIBUTE_UNUSED zval *_get_obj_zval_ptr(int op_type,
                                                            znode_op op,
                                                            int type EXECUTE_DATA_DC OPLINE_DC) {
    if (op_type == IS_UNUSED) {
        return &EX(This);
    }
    return get_zval_ptr(op_type, op, type);
}

static inline ZEND_ATTRIBUTE_UNUSED zval *_get_obj_zval_ptr_undef(int op_type,
                                                                  znode_op op,
                                                                  int type EXECUTE_DATA_DC OPLINE_DC) {
    if (op_type == IS_UNUSED) {
        return &EX(This);
    }
    return get_zval_ptr_undef(op_type, op, type);
}

static inline ZEND_ATTRIBUTE_UNUSED zval *_get_obj_zval_ptr_ptr(int op_type, znode_op node, int type EXECUTE_DATA_DC) {
    if (op_type == IS_UNUSED) {
        return &EX(This);
    }
    return get_zval_ptr_ptr(op_type, node, type);
}

static zend_never_inline ZEND_COLD void ZEND_FASTCALL zend_undefined_index(const zend_string *offset) {
    zend_error(E_WARNING, "Undefined array key \"%s\"", ZSTR_VAL(offset));
}

static zend_never_inline ZEND_COLD void ZEND_FASTCALL zend_undefined_offset(zend_long lval) {
    zend_error(E_WARNING, "Undefined array key " ZEND_LONG_FMT, lval);
}

static zend_never_inline ZEND_COLD void ZEND_FASTCALL zend_illegal_array_offset_access(const zval *offset) {
    zend_illegal_container_offset(ZSTR_KNOWN(ZEND_STR_ARRAY), offset, BP_VAR_RW);
}

static zend_never_inline uint8_t slow_index_convert(HashTable *ht, const zval *dim, zend_value *value EXECUTE_DATA_DC) {
    switch (Z_TYPE_P(dim)) {
    case IS_UNDEF: {
        /* The array may be destroyed while throwing the notice.
         * Temporarily increase the refcount to detect this situation. */
        if (!(GC_FLAGS(ht) & IS_ARRAY_IMMUTABLE)) {
            GC_ADDREF(ht);
        }
        ZVAL_UNDEFINED_OP2();
        if (!(GC_FLAGS(ht) & IS_ARRAY_IMMUTABLE) && !GC_DELREF(ht)) {
            zend_array_destroy(ht);
            return IS_NULL;
        }
        if (EG(exception)) {
            return IS_NULL;
        }
        ZEND_FALLTHROUGH;
    }
    case IS_NULL:
        value->str = ZSTR_EMPTY_ALLOC();
        return IS_STRING;
    case IS_DOUBLE:
        value->lval = zend_dval_to_lval(Z_DVAL_P(dim));
        if (!zend_is_long_compatible(Z_DVAL_P(dim), value->lval)) {
            /* The array may be destroyed while throwing the notice.
             * Temporarily increase the refcount to detect this situation. */
            if (!(GC_FLAGS(ht) & IS_ARRAY_IMMUTABLE)) {
                GC_ADDREF(ht);
            }
            zend_incompatible_double_to_long_error(Z_DVAL_P(dim));
            if (!(GC_FLAGS(ht) & IS_ARRAY_IMMUTABLE) && !GC_DELREF(ht)) {
                zend_array_destroy(ht);
                return IS_NULL;
            }
            if (EG(exception)) {
                return IS_NULL;
            }
        }
        return IS_LONG;
    case IS_RESOURCE:
        /* The array may be destroyed while throwing the notice.
         * Temporarily increase the refcount to detect this situation. */
        if (!(GC_FLAGS(ht) & IS_ARRAY_IMMUTABLE)) {
            GC_ADDREF(ht);
        }
        zend_use_resource_as_offset(dim);
        if (!(GC_FLAGS(ht) & IS_ARRAY_IMMUTABLE) && !GC_DELREF(ht)) {
            zend_array_destroy(ht);
            return IS_NULL;
        }
        if (EG(exception)) {
            return IS_NULL;
        }
        value->lval = Z_RES_HANDLE_P(dim);
        return IS_LONG;
    case IS_FALSE:
        value->lval = 0;
        return IS_LONG;
    case IS_TRUE:
        value->lval = 1;
        return IS_LONG;
    default:
        zend_illegal_array_offset_access(dim);
        return IS_NULL;
    }
}

static zend_never_inline uint8_t slow_index_convert_w(HashTable *ht,
                                                      const zval *dim,
                                                      zend_value *value EXECUTE_DATA_DC) {
    switch (Z_TYPE_P(dim)) {
    case IS_UNDEF: {
        /* The array may be destroyed while throwing the notice.
         * Temporarily increase the refcount to detect this situation. */
        if (!(GC_FLAGS(ht) & IS_ARRAY_IMMUTABLE)) {
            GC_ADDREF(ht);
        }
        ZVAL_UNDEFINED_OP2();
        if (!(GC_FLAGS(ht) & IS_ARRAY_IMMUTABLE) && GC_DELREF(ht) != 1) {
            if (!GC_REFCOUNT(ht)) {
                zend_array_destroy(ht);
            }
            return IS_NULL;
        }
        if (EG(exception)) {
            return IS_NULL;
        }
        ZEND_FALLTHROUGH;
    }
    case IS_NULL:
        value->str = ZSTR_EMPTY_ALLOC();
        return IS_STRING;
    case IS_DOUBLE:
        value->lval = zend_dval_to_lval(Z_DVAL_P(dim));
        if (!zend_is_long_compatible(Z_DVAL_P(dim), value->lval)) {
            /* The array may be destroyed while throwing the notice.
             * Temporarily increase the refcount to detect this situation. */
            if (!(GC_FLAGS(ht) & IS_ARRAY_IMMUTABLE)) {
                GC_ADDREF(ht);
            }
            zend_incompatible_double_to_long_error(Z_DVAL_P(dim));
            if (!(GC_FLAGS(ht) & IS_ARRAY_IMMUTABLE) && GC_DELREF(ht) != 1) {
                if (!GC_REFCOUNT(ht)) {
                    zend_array_destroy(ht);
                }
                return IS_NULL;
            }
            if (EG(exception)) {
                return IS_NULL;
            }
        }
        return IS_LONG;
    case IS_RESOURCE:
        /* The array may be destroyed while throwing the notice.
         * Temporarily increase the refcount to detect this situation. */
        if (!(GC_FLAGS(ht) & IS_ARRAY_IMMUTABLE)) {
            GC_ADDREF(ht);
        }
        zend_use_resource_as_offset(dim);
        if (!(GC_FLAGS(ht) & IS_ARRAY_IMMUTABLE) && GC_DELREF(ht) != 1) {
            if (!GC_REFCOUNT(ht)) {
                zend_array_destroy(ht);
            }
            return IS_NULL;
        }
        if (EG(exception)) {
            return IS_NULL;
        }
        value->lval = Z_RES_HANDLE_P(dim);
        return IS_LONG;
    case IS_FALSE:
        value->lval = 0;
        return IS_LONG;
    case IS_TRUE:
        value->lval = 1;
        return IS_LONG;
    default:
        zend_illegal_array_offset_access(dim);
        return IS_NULL;
    }
}

static zend_always_inline zval *zend_fetch_dimension_address_inner(HashTable *ht,
                                                                   const zval *dim,
                                                                   int dim_type,
                                                                   int type EXECUTE_DATA_DC) {
    zval *retval = NULL;
    zend_string *offset_key;
    zend_ulong hval;

try_again:
    if (EXPECTED(Z_TYPE_P(dim) == IS_LONG)) {
        hval = Z_LVAL_P(dim);
    num_index:
        if (type != BP_VAR_W) {
            ZEND_HASH_INDEX_FIND(ht, hval, retval, num_undef);
            return retval;
        num_undef:
            switch (type) {
            case BP_VAR_R:
                zend_undefined_offset(hval);
                ZEND_FALLTHROUGH;
            case BP_VAR_UNSET:
            case BP_VAR_IS:
                retval = &EG(uninitialized_zval);
                break;
            case BP_VAR_RW:
                retval = zend_undefined_offset_write(ht, hval);
                break;
            }
        } else {
            ZEND_HASH_INDEX_LOOKUP(ht, hval, retval);
        }
    } else if (EXPECTED(Z_TYPE_P(dim) == IS_STRING)) {
        offset_key = Z_STR_P(dim);
        if (ZEND_CONST_COND(dim_type != IS_CONST, 1)) {
            if (ZEND_HANDLE_NUMERIC(offset_key, hval)) {
                goto num_index;
            }
        }
    str_index:
        if (type != BP_VAR_W) {
            retval = zend_hash_find_ex(ht, offset_key, ZEND_CONST_COND(dim_type == IS_CONST, 0));
            if (!retval) {
                switch (type) {
                case BP_VAR_R:
                    zend_undefined_index(offset_key);
                    ZEND_FALLTHROUGH;
                case BP_VAR_UNSET:
                case BP_VAR_IS:
                    retval = &EG(uninitialized_zval);
                    break;
                case BP_VAR_RW:
                    retval = zend_undefined_index_write(ht, offset_key);
                    break;
                }
            }
        } else {
            retval = zend_hash_lookup(ht, offset_key);
        }
    } else if (EXPECTED(Z_TYPE_P(dim) == IS_REFERENCE)) {
        dim = Z_REFVAL_P(dim);
        goto try_again;
    } else {
        zend_value val;
        uint8_t t;

        if (type != BP_VAR_W && type != BP_VAR_RW) {
            t = slow_index_convert(ht, dim, &val EXECUTE_DATA_CC);
        } else {
            t = slow_index_convert_w(ht, dim, &val EXECUTE_DATA_CC);
        }
        if (t == IS_STRING) {
            offset_key = val.str;
            goto str_index;
        } else if (t == IS_LONG) {
            hval = val.lval;
            goto num_index;
        } else {
            retval = (type == BP_VAR_W || type == BP_VAR_RW) ? NULL : &EG(uninitialized_zval);
        }
    }
    return retval;
}

static zend_never_inline zval *ZEND_FASTCALL
zend_fetch_dimension_address_inner_RW_CONST(HashTable *ht, const zval *dim EXECUTE_DATA_DC) {
    return zend_fetch_dimension_address_inner(ht, dim, IS_CONST, BP_VAR_RW EXECUTE_DATA_CC);
}

static zend_never_inline zval *ZEND_FASTCALL zend_fetch_dimension_address_inner_RW(HashTable *ht,
                                                                                   const zval *dim EXECUTE_DATA_DC) {
    return zend_fetch_dimension_address_inner(ht, dim, IS_TMP_VAR, BP_VAR_RW EXECUTE_DATA_CC);
}

static zend_never_inline zval *ZEND_FASTCALL zend_fetch_dimension_address_inner_W(HashTable *ht,
                                                                                  const zval *dim EXECUTE_DATA_DC) {
    return zend_fetch_dimension_address_inner(ht, dim, IS_TMP_VAR, BP_VAR_W EXECUTE_DATA_CC);
}

static zend_never_inline zval *ZEND_FASTCALL
zend_fetch_dimension_address_inner_W_CONST(HashTable *ht, const zval *dim EXECUTE_DATA_DC) {
    return zend_fetch_dimension_address_inner(ht, dim, IS_CONST, BP_VAR_W EXECUTE_DATA_CC);
}

static zend_always_inline int zend_binary_op(zval *ret, zval *op1, zval *op2 OPLINE_DC) {
    static const binary_op_type zend_binary_ops[] = {add_function,
                                                     sub_function,
                                                     mul_function,
                                                     div_function,
                                                     mod_function,
                                                     shift_left_function,
                                                     shift_right_function,
                                                     concat_function,
                                                     bitwise_or_function,
                                                     bitwise_and_function,
                                                     bitwise_xor_function,
                                                     pow_function};
    /* size_t cast makes GCC to better optimize 64-bit PIC code */
    size_t opcode = (size_t) opline->extended_value;

    return zend_binary_ops[opcode - ZEND_ADD](ret, op1, op2);
}

static zend_never_inline void zend_binary_assign_op_typed_ref(zend_reference *ref,
                                                              zval *value OPLINE_DC EXECUTE_DATA_DC) {
    zval z_copy;

    /* Make sure that in-place concatenation is used if the LHS is a string. */
    if (opline->extended_value == ZEND_CONCAT && Z_TYPE(ref->val) == IS_STRING) {
        concat_function(&ref->val, &ref->val, value);
        ZEND_ASSERT(Z_TYPE(ref->val) == IS_STRING && "Concat should return string");
        return;
    }

    zend_binary_op(&z_copy, &ref->val, value OPLINE_CC);
    if (EXPECTED(zend_verify_ref_assignable_zval(ref, &z_copy, EX_USES_STRICT_TYPES()))) {
        zval_ptr_dtor(&ref->val);
        ZVAL_COPY_VALUE(&ref->val, &z_copy);
    } else {
        zval_ptr_dtor(&z_copy);
    }
}
