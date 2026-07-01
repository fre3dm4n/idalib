use std::marker::PhantomData;

use crate::ffi::hexrays::{
    cblock_iter, cblock_t, cfunc_t, cfuncptr_t, cinsn_t, idalib_hexrays_assignments_get,
    idalib_hexrays_assignments_len, idalib_hexrays_call_edges_get, idalib_hexrays_call_edges_len,
    idalib_hexrays_cblock_iter, idalib_hexrays_cblock_iter_next, idalib_hexrays_cblock_len,
    idalib_hexrays_cfunc_alias_param_positions, idalib_hexrays_cfunc_apply_lvar_info,
    idalib_hexrays_cfunc_apply_param_info, idalib_hexrays_cfunc_assignments,
    idalib_hexrays_cfunc_call_edges, idalib_hexrays_cfunc_lvar_info,
    idalib_hexrays_cfunc_param_info, idalib_hexrays_cfunc_param_lvar_idx,
    idalib_hexrays_cfunc_pseudocode, idalib_hexrays_cfunc_target_calls,
    idalib_hexrays_cfunc_this_expressions, idalib_hexrays_cfuncptr_inner,
    idalib_hexrays_i32_vec_get, idalib_hexrays_i32_vec_len, idalib_hexrays_target_calls_get,
    idalib_hexrays_target_calls_len, idalib_hexrays_this_expressions_get,
    idalib_hexrays_this_expressions_len,
};
use crate::idb::IDB;

pub use crate::ffi::hexrays::{HexRaysError, HexRaysErrorCode};

pub fn parse_decls_file(path: &str) -> i32 {
    unsafe { crate::ffi::hexrays::idalib_parse_decls_file(path) }
}

pub fn named_type_exists(name: &str) -> bool {
    unsafe { crate::ffi::hexrays::idalib_named_type_exists(name) }
}

pub fn save_database_with_backup() -> bool {
    unsafe { crate::ffi::hexrays::idalib_save_database_with_backup() }
}

pub struct CFunction<'a> {
    ptr: *mut cfunc_t,
    _obj: cxx::UniquePtr<cfuncptr_t>,
    _marker: PhantomData<&'a IDB>,
}

pub struct CBlock<'a> {
    ptr: *mut cblock_t,
    _marker: PhantomData<&'a ()>,
}

pub struct CBlockIter<'a> {
    it: cxx::UniquePtr<cblock_iter>,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Iterator for CBlockIter<'a> {
    type Item = CInsn<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let ptr = unsafe { idalib_hexrays_cblock_iter_next(self.it.pin_mut()) };

        if ptr.is_null() {
            None
        } else {
            Some(CInsn {
                ptr,
                _marker: PhantomData,
            })
        }
    }
}

pub struct CInsn<'a> {
    #[allow(unused)]
    ptr: *mut cinsn_t,
    _marker: PhantomData<&'a ()>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LVarInfo {
    pub index: i32,
    pub name: String,
    pub type_text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assignment {
    pub lhs_idx: i32,
    pub rhs_idx: Option<i32>,
    pub simple: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEdge {
    pub caller_ea: crate::Address,
    pub callee_ea: crate::Address,
    pub call_ea: crate::Address,
    pub arg_pos: i32,
    pub arg_idx: i32,
    pub arg_text: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetCall {
    pub call_ea: crate::Address,
    pub target_arg_pos: i32,
    pub tracked_var_idx: i32,
    pub tracked_arg_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThisExpression {
    pub func_ea: crate::Address,
    pub expr_ea: crate::Address,
    pub op: i32,
    pub alias_idx: i32,
    pub op_name: String,
    pub kind: String,
    pub text: String,
    pub alias_text: String,
}

impl<'a> CFunction<'a> {
    pub(crate) fn new(obj: cxx::UniquePtr<cfuncptr_t>) -> Option<Self> {
        let ptr = unsafe { idalib_hexrays_cfuncptr_inner(obj.as_ref().expect("valid pointer")) };

        if ptr.is_null() {
            return None;
        }

        Some(Self {
            ptr,
            _obj: obj,
            _marker: PhantomData,
        })
    }

    pub fn pseudocode(&self) -> String {
        unsafe { idalib_hexrays_cfunc_pseudocode(self.ptr) }
    }

    pub fn param_lvar_idx(&self, param_pos: i32) -> Option<i32> {
        let idx = unsafe { idalib_hexrays_cfunc_param_lvar_idx(self.ptr, param_pos) };
        (idx >= 0).then_some(idx)
    }

    pub fn lvar_info(&self, index: i32) -> Option<LVarInfo> {
        let info = unsafe { idalib_hexrays_cfunc_lvar_info(self.ptr, index) };
        info.valid.then(|| LVarInfo {
            index: info.index,
            name: info.name,
            type_text: info.type_,
        })
    }

    pub fn param_info(&self, param_pos: i32) -> Option<LVarInfo> {
        let info = unsafe { idalib_hexrays_cfunc_param_info(self.ptr, param_pos) };
        info.valid.then(|| LVarInfo {
            index: info.index,
            name: info.name,
            type_text: info.type_,
        })
    }

    pub fn assignments(&self) -> Vec<Assignment> {
        let items = unsafe { idalib_hexrays_cfunc_assignments(self.ptr) };
        let Some(items) = items.as_ref() else {
            return Vec::new();
        };
        let len = unsafe { idalib_hexrays_assignments_len(items) };
        (0..len)
            .map(|index| unsafe { idalib_hexrays_assignments_get(items, index) })
            .map(|item| Assignment {
                lhs_idx: item.lhs_idx,
                rhs_idx: (item.rhs_idx >= 0).then_some(item.rhs_idx),
                simple: item.simple,
            })
            .collect()
    }

    pub fn call_edges(&self, aliases: &[i32], kind: &str) -> Vec<CallEdge> {
        let items = unsafe { idalib_hexrays_cfunc_call_edges(self.ptr, aliases, kind) };
        let Some(items) = items.as_ref() else {
            return Vec::new();
        };
        let len = unsafe { idalib_hexrays_call_edges_len(items) };
        (0..len)
            .map(|index| unsafe { idalib_hexrays_call_edges_get(items, index) })
            .map(|item| CallEdge {
                caller_ea: item.caller_ea,
                callee_ea: item.callee_ea,
                call_ea: item.call_ea,
                arg_pos: item.arg_pos,
                arg_idx: item.arg_idx,
                arg_text: item.arg_text,
                kind: item.kind,
            })
            .collect()
    }

    pub fn target_calls(
        &self,
        target_ea: crate::Address,
        target_param_pos: i32,
    ) -> Vec<TargetCall> {
        let items =
            unsafe { idalib_hexrays_cfunc_target_calls(self.ptr, target_ea, target_param_pos) };
        let Some(items) = items.as_ref() else {
            return Vec::new();
        };
        let len = unsafe { idalib_hexrays_target_calls_len(items) };
        (0..len)
            .map(|index| unsafe { idalib_hexrays_target_calls_get(items, index) })
            .map(|item| TargetCall {
                call_ea: item.call_ea,
                target_arg_pos: item.target_arg_pos,
                tracked_var_idx: item.tracked_var_idx,
                tracked_arg_text: item.tracked_arg_text,
            })
            .collect()
    }

    pub fn this_expressions(&self, aliases: &[i32]) -> Vec<ThisExpression> {
        let items = unsafe { idalib_hexrays_cfunc_this_expressions(self.ptr, aliases) };
        let Some(items) = items.as_ref() else {
            return Vec::new();
        };
        let len = unsafe { idalib_hexrays_this_expressions_len(items) };
        (0..len)
            .map(|index| unsafe { idalib_hexrays_this_expressions_get(items, index) })
            .map(|item| ThisExpression {
                func_ea: item.func_ea,
                expr_ea: item.expr_ea,
                op: item.op,
                alias_idx: item.alias_idx,
                op_name: item.op_name,
                kind: item.kind,
                text: item.text,
                alias_text: item.alias_text,
            })
            .collect()
    }

    pub fn alias_param_positions(&self, aliases: &[i32]) -> Vec<i32> {
        let items = unsafe { idalib_hexrays_cfunc_alias_param_positions(self.ptr, aliases) };
        let Some(items) = items.as_ref() else {
            return Vec::new();
        };
        let len = unsafe { idalib_hexrays_i32_vec_len(items) };
        (0..len)
            .map(|index| unsafe { idalib_hexrays_i32_vec_get(items, index) })
            .collect()
    }

    pub fn apply_lvar_info(
        &self,
        lvar_idx: i32,
        name: &str,
        type_decl: &str,
        persist: bool,
    ) -> bool {
        unsafe {
            idalib_hexrays_cfunc_apply_lvar_info(self.ptr, lvar_idx, name, type_decl, persist)
        }
    }

    pub fn apply_param_info(
        &self,
        param_pos: i32,
        name: &str,
        type_decl: &str,
        persist: bool,
    ) -> bool {
        unsafe {
            idalib_hexrays_cfunc_apply_param_info(self.ptr, param_pos, name, type_decl, persist)
        }
    }

    fn as_cfunc(&self) -> &cfunc_t {
        unsafe { self.ptr.as_ref().expect("valid pointer") }
    }

    pub fn body(&self) -> CBlock<'_> {
        let cf = self.as_cfunc();
        let ptr = unsafe { cf.body.__bindgen_anon_1.cblock };

        CBlock {
            ptr,
            _marker: PhantomData,
        }
    }
}

impl<'a> CBlock<'a> {
    pub fn iter(&self) -> CBlockIter<'_> {
        CBlockIter {
            it: unsafe { idalib_hexrays_cblock_iter(self.ptr) },
            _marker: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        unsafe { idalib_hexrays_cblock_len(self.ptr) }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
