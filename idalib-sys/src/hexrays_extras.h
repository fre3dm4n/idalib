#pragma once

#include "hexrays.hpp"
#include "ida.hpp"
#include "lines.hpp"
#include "loader.hpp"
#include "pro.h"
#include "typeinf.hpp"

#include <cstdint>
#include <set>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "cxx.h"

#ifndef CXXBRIDGE1_STRUCT_hexrays_error_t
#define CXXBRIDGE1_STRUCT_hexrays_error_t
struct hexrays_error_t final {
  ::std::int32_t code;
  ::std::uint64_t addr;
  ::rust::String desc;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_hexrays_error_t

struct cblock_iter {
  qlist<cinsn_t>::iterator start;
  qlist<cinsn_t>::iterator end;

  cblock_iter(cblock_t *b) : start(b->begin()), end(b->end()) {}
};

#ifndef CXXBRIDGE1_STRUCT_hexrays_lvar_info_t
#define CXXBRIDGE1_STRUCT_hexrays_lvar_info_t
struct hexrays_lvar_info_t final {
  ::std::int32_t index;
  rust::String name;
  rust::String type_;
  bool valid;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_hexrays_lvar_info_t

#ifndef CXXBRIDGE1_STRUCT_hexrays_assignment_t
#define CXXBRIDGE1_STRUCT_hexrays_assignment_t
struct hexrays_assignment_t final {
  ::std::int32_t lhs_idx;
  ::std::int32_t rhs_idx;
  bool simple;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_hexrays_assignment_t

#ifndef CXXBRIDGE1_STRUCT_hexrays_call_edge_t
#define CXXBRIDGE1_STRUCT_hexrays_call_edge_t
struct hexrays_call_edge_t final {
  ::std::uint64_t caller_ea;
  ::std::uint64_t callee_ea;
  ::std::uint64_t call_ea;
  ::std::int32_t arg_pos;
  ::std::int32_t arg_idx;
  rust::String arg_text;
  rust::String kind;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_hexrays_call_edge_t

#ifndef CXXBRIDGE1_STRUCT_hexrays_target_call_t
#define CXXBRIDGE1_STRUCT_hexrays_target_call_t
struct hexrays_target_call_t final {
  ::std::uint64_t call_ea;
  ::std::int32_t target_arg_pos;
  ::std::int32_t tracked_var_idx;
  rust::String tracked_arg_text;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_hexrays_target_call_t

#ifndef CXXBRIDGE1_STRUCT_hexrays_this_expr_t
#define CXXBRIDGE1_STRUCT_hexrays_this_expr_t
struct hexrays_this_expr_t final {
  ::std::uint64_t func_ea;
  ::std::uint64_t expr_ea;
  ::std::int32_t op;
  ::std::int32_t alias_idx;
  rust::String op_name;
  rust::String kind;
  rust::String text;
  rust::String alias_text;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_hexrays_this_expr_t

using hexrays_assignment_vec = std::vector<hexrays_assignment_t>;
using hexrays_call_edge_vec = std::vector<hexrays_call_edge_t>;
using hexrays_target_call_vec = std::vector<hexrays_target_call_t>;
using hexrays_this_expr_vec = std::vector<hexrays_this_expr_t>;
using hexrays_i32_vec = std::vector<int32_t>;

static inline bool idalib_hexrays_is_assignment_op(ctype_t op) {
  return op >= cot_asg && op <= cot_asgumod;
}

static inline rust::String idalib_hexrays_item_text(const citem_t *item,
                                                    const cfunc_t *func) {
  qstring buf;
  item->print1(&buf, func);
  qstring clean;
  tag_remove(&clean, buf.c_str());
  return rust::String(clean.c_str());
}

static inline int idalib_hexrays_expr_size(const cexpr_t *expr) {
  if (expr == nullptr) {
    return -1;
  }
  return int(expr->type.get_size());
}

static inline const cexpr_t *
idalib_hexrays_unwrap_value_expr_const(const cexpr_t *expr,
                                       bool require_pointer_width) {
  while (expr != nullptr && (expr->op == cot_cast || expr->op == cot_comma)) {
    if (expr->op == cot_cast) {
      int size = idalib_hexrays_expr_size(expr);
      if (require_pointer_width && size != -1 && size != inf_get_app_bitness() / 8) {
        return nullptr;
      }
      expr = expr->x;
    } else {
      expr = expr->y;
    }
  }
  return expr;
}

static inline cexpr_t *idalib_hexrays_unwrap_value_expr(cexpr_t *expr,
                                                        bool require_pointer_width) {
  return const_cast<cexpr_t *>(
      idalib_hexrays_unwrap_value_expr_const(expr, require_pointer_width));
}

static inline int idalib_hexrays_direct_var_idx(const cexpr_t *expr) {
  expr = idalib_hexrays_unwrap_value_expr_const(expr, true);
  if (expr != nullptr && expr->op == cot_var) {
    return expr->v.idx;
  }
  return -1;
}

static inline const char *idalib_hexrays_op_name(ctype_t op) {
  switch (op) {
  case cot_empty: return "cot_empty";
  case cot_comma: return "cot_comma";
  case cot_asg: return "cot_asg";
  case cot_asgbor: return "cot_asgbor";
  case cot_asgxor: return "cot_asgxor";
  case cot_asgband: return "cot_asgband";
  case cot_asgadd: return "cot_asgadd";
  case cot_asgsub: return "cot_asgsub";
  case cot_asgmul: return "cot_asgmul";
  case cot_asgsshr: return "cot_asgsshr";
  case cot_asgushr: return "cot_asgushr";
  case cot_asgshl: return "cot_asgshl";
  case cot_asgsdiv: return "cot_asgsdiv";
  case cot_asgudiv: return "cot_asgudiv";
  case cot_asgsmod: return "cot_asgsmod";
  case cot_asgumod: return "cot_asgumod";
  case cot_tern: return "cot_tern";
  case cot_lor: return "cot_lor";
  case cot_land: return "cot_land";
  case cot_bor: return "cot_bor";
  case cot_xor: return "cot_xor";
  case cot_band: return "cot_band";
  case cot_eq: return "cot_eq";
  case cot_ne: return "cot_ne";
  case cot_sge: return "cot_sge";
  case cot_uge: return "cot_uge";
  case cot_sle: return "cot_sle";
  case cot_ule: return "cot_ule";
  case cot_sgt: return "cot_sgt";
  case cot_ugt: return "cot_ugt";
  case cot_slt: return "cot_slt";
  case cot_ult: return "cot_ult";
  case cot_sshr: return "cot_sshr";
  case cot_ushr: return "cot_ushr";
  case cot_shl: return "cot_shl";
  case cot_add: return "cot_add";
  case cot_sub: return "cot_sub";
  case cot_mul: return "cot_mul";
  case cot_sdiv: return "cot_sdiv";
  case cot_udiv: return "cot_udiv";
  case cot_smod: return "cot_smod";
  case cot_umod: return "cot_umod";
  case cot_fadd: return "cot_fadd";
  case cot_fsub: return "cot_fsub";
  case cot_fmul: return "cot_fmul";
  case cot_fdiv: return "cot_fdiv";
  case cot_fneg: return "cot_fneg";
  case cot_neg: return "cot_neg";
  case cot_cast: return "cot_cast";
  case cot_lnot: return "cot_lnot";
  case cot_bnot: return "cot_bnot";
  case cot_ptr: return "cot_ptr";
  case cot_ref: return "cot_ref";
  case cot_postinc: return "cot_postinc";
  case cot_postdec: return "cot_postdec";
  case cot_preinc: return "cot_preinc";
  case cot_predec: return "cot_predec";
  case cot_call: return "cot_call";
  case cot_idx: return "cot_idx";
  case cot_memref: return "cot_memref";
  case cot_memptr: return "cot_memptr";
  case cot_num: return "cot_num";
  case cot_fnum: return "cot_fnum";
  case cot_str: return "cot_str";
  case cot_obj: return "cot_obj";
  case cot_var: return "cot_var";
  case cot_insn: return "cot_insn";
  case cot_sizeof: return "cot_sizeof";
  case cot_helper: return "cot_helper";
  case cot_type: return "cot_type";
  default: return "cot_unknown";
  }
}

static bool idalib_hexrays_expr_find_alias(const cexpr_t *expr,
                                           const std::set<int> *aliases,
                                           const cexpr_t **alias_expr,
                                           int *alias_idx) {
  if (expr == nullptr) {
    return false;
  }

  if (expr->op == cot_var && aliases->find(expr->v.idx) != aliases->end()) {
    if (alias_expr != nullptr) {
      *alias_expr = expr;
    }
    if (alias_idx != nullptr) {
      *alias_idx = expr->v.idx;
    }
    return true;
  }

  if (op_uses_x(expr->op) &&
      idalib_hexrays_expr_find_alias(expr->x, aliases, alias_expr, alias_idx)) {
    return true;
  }
  if (expr->op == cot_call && expr->a != nullptr) {
    for (const carg_t &arg : *expr->a) {
      if (idalib_hexrays_expr_find_alias(&arg, aliases, alias_expr, alias_idx)) {
        return true;
      }
    }
  }
  if (op_uses_y(expr->op)) {
    if (idalib_hexrays_expr_find_alias(expr->y, aliases, alias_expr, alias_idx)) {
      return true;
    }
  }
  if (op_uses_z(expr->op) &&
      idalib_hexrays_expr_find_alias(expr->z, aliases, alias_expr, alias_idx)) {
    return true;
  }

  return false;
}

static inline bool idalib_hexrays_direct_alias_expr(const cexpr_t *expr,
                                                    const std::set<int> *aliases) {
  int idx = idalib_hexrays_direct_var_idx(expr);
  return idx >= 0 && aliases->find(idx) != aliases->end();
}

static bool idalib_hexrays_expr_has_direct_alias_operand(
    const cexpr_t *expr, const std::set<int> *aliases) {
  if (expr == nullptr) {
    return false;
  }
  if (op_uses_x(expr->op) && idalib_hexrays_direct_alias_expr(expr->x, aliases)) {
    return true;
  }
  if (expr->op == cot_call && expr->a != nullptr) {
    for (const carg_t &arg : *expr->a) {
      if (idalib_hexrays_direct_alias_expr(&arg, aliases)) {
        return true;
      }
    }
  }
  if (op_uses_y(expr->op)) {
    if (idalib_hexrays_direct_alias_expr(expr->y, aliases)) {
      return true;
    }
  }
  if (op_uses_z(expr->op) && idalib_hexrays_direct_alias_expr(expr->z, aliases)) {
    return true;
  }
  return false;
}

static bool idalib_hexrays_expr_find_alias_field_access(
    const cexpr_t *expr, const std::set<int> *aliases,
    const cexpr_t **alias_expr, int *alias_idx) {
  if (expr == nullptr) {
    return false;
  }

  if ((expr->op == cot_memptr || expr->op == cot_memref) &&
      idalib_hexrays_expr_find_alias(expr->x, aliases, alias_expr, alias_idx)) {
    return true;
  }
  if ((expr->op == cot_ptr || expr->op == cot_idx) &&
      idalib_hexrays_expr_find_alias(expr->x, aliases, alias_expr, alias_idx)) {
    return true;
  }

  if (op_uses_x(expr->op) &&
      idalib_hexrays_expr_find_alias_field_access(expr->x, aliases, alias_expr, alias_idx)) {
    return true;
  }
  if (expr->op == cot_call && expr->a != nullptr) {
    for (const carg_t &arg : *expr->a) {
      if (idalib_hexrays_expr_find_alias_field_access(&arg, aliases, alias_expr, alias_idx)) {
        return true;
      }
    }
  }
  if (op_uses_y(expr->op) &&
      idalib_hexrays_expr_find_alias_field_access(expr->y, aliases, alias_expr, alias_idx)) {
    return true;
  }
  if (op_uses_z(expr->op) &&
      idalib_hexrays_expr_find_alias_field_access(expr->z, aliases, alias_expr, alias_idx)) {
    return true;
  }

  return false;
}

static rust::String idalib_hexrays_this_expr_kind(const cexpr_t *expr,
                                                  const std::set<int> *aliases) {
  if (expr == nullptr) {
    return rust::String("unknown");
  }

  if (expr->op == cot_var && aliases->find(expr->v.idx) != aliases->end()) {
    return rust::String("alias");
  }
  if (idalib_hexrays_is_assignment_op(expr->op)) {
    if (idalib_hexrays_expr_find_alias(expr->x, aliases, nullptr, nullptr)) {
      return rust::String("assignment-write");
    }
    return rust::String("assignment-read");
  }
  if (expr->op == cot_memptr || expr->op == cot_memref) {
    return rust::String("member-access");
  }
  if (expr->op == cot_ptr) {
    return rust::String("deref");
  }
  if (expr->op == cot_ref) {
    return rust::String("address-of");
  }
  if (expr->op == cot_idx) {
    return rust::String("index");
  }
  if (expr->op == cot_call) {
    if (expr->x != nullptr && idalib_hexrays_expr_find_alias(expr->x, aliases, nullptr, nullptr)) {
      return rust::String("call-target");
    }
    return rust::String("call-argument");
  }
  if (expr->op == cot_add || expr->op == cot_sub ||
      expr->op == cot_asgadd || expr->op == cot_asgsub) {
    return rust::String("pointer-arithmetic");
  }
  if (is_prepost(expr->op)) {
    return rust::String("mutation");
  }
  if (idalib_hexrays_expr_has_direct_alias_operand(expr, aliases)) {
    return rust::String("direct-use");
  }
  return rust::String("containing");
}

static void idalib_hexrays_collect_call_if_matches(
    const cfunc_t *func, const cexpr_t *expr, const std::set<int> *aliases,
    const char *kind, std::vector<hexrays_call_edge_t> *out) {
  if (expr->op != cot_call || expr->a == nullptr || expr->a->empty()) {
    return;
  }

  const cexpr_t *callee = idalib_hexrays_unwrap_value_expr_const(expr->x, false);
  if (callee == nullptr || callee->op != cot_obj || callee->obj_ea == BADADDR) {
    return;
  }

  func_t *callee_func = get_func(callee->obj_ea);
  if (callee_func == nullptr) {
    return;
  }

  for (size_t arg_pos = 0; arg_pos < expr->a->size(); arg_pos++) {
    const cexpr_t *arg = &expr->a->at(arg_pos);
    int arg_idx = idalib_hexrays_direct_var_idx(arg);
    if (arg_idx < 0 || aliases->find(arg_idx) == aliases->end()) {
      continue;
    }

    out->push_back(hexrays_call_edge_t{
        func->entry_ea,
        callee_func->start_ea,
        expr->ea,
        int(arg_pos),
        arg_idx,
        idalib_hexrays_item_text(arg, func),
        rust::String(kind),
    });
  }
}

static void idalib_hexrays_collect_target_call_if_matches(
    const cfunc_t *func, const cexpr_t *expr, uint64_t target_ea,
    int target_param_pos, std::vector<hexrays_target_call_t> *out) {
  if (expr->op != cot_call || expr->a == nullptr ||
      target_param_pos < 0 || size_t(target_param_pos) >= expr->a->size()) {
    return;
  }

  const cexpr_t *callee = idalib_hexrays_unwrap_value_expr_const(expr->x, false);
  if (callee == nullptr || callee->op != cot_obj || callee->obj_ea == BADADDR) {
    return;
  }

  func_t *callee_func = get_func(callee->obj_ea);
  if (callee_func == nullptr || callee_func->start_ea != target_ea) {
    return;
  }

  const cexpr_t *arg = &expr->a->at(size_t(target_param_pos));
  int tracked_var_idx = idalib_hexrays_direct_var_idx(arg);
  if (tracked_var_idx < 0) {
    return;
  }

  out->push_back(hexrays_target_call_t{
      expr->ea,
      target_param_pos,
      tracked_var_idx,
      idalib_hexrays_item_text(arg, func),
  });
}

struct idalib_assignment_collector_t : public ctree_visitor_t {
  std::vector<hexrays_assignment_t> *out;

  explicit idalib_assignment_collector_t(std::vector<hexrays_assignment_t> *_out)
      : ctree_visitor_t(CV_FAST), out(_out) {}

  int idaapi visit_expr(cexpr_t *expr) override {
    if (expr != nullptr && idalib_hexrays_is_assignment_op(expr->op)) {
      int lhs_idx = idalib_hexrays_direct_var_idx(expr->x);
      if (lhs_idx >= 0) {
        out->push_back(hexrays_assignment_t{
            lhs_idx,
            idalib_hexrays_direct_var_idx(expr->y),
            expr->op == cot_asg,
        });
      }
    }
    return 0;
  }
};

struct idalib_call_edge_collector_t : public ctree_visitor_t {
  const cfunc_t *func;
  const std::set<int> *aliases;
  const char *kind;
  std::vector<hexrays_call_edge_t> *out;

  idalib_call_edge_collector_t(const cfunc_t *_func,
                               const std::set<int> *_aliases,
                               const char *_kind,
                               std::vector<hexrays_call_edge_t> *_out)
      : ctree_visitor_t(CV_FAST), func(_func), aliases(_aliases), kind(_kind), out(_out) {}

  int idaapi visit_expr(cexpr_t *expr) override {
    if (expr != nullptr && expr->op == cot_call) {
      idalib_hexrays_collect_call_if_matches(func, expr, aliases, kind, out);
    }
    return 0;
  }
};

struct idalib_target_call_collector_t : public ctree_visitor_t {
  const cfunc_t *func;
  uint64_t target_ea;
  int target_param_pos;
  std::vector<hexrays_target_call_t> *out;

  idalib_target_call_collector_t(const cfunc_t *_func,
                                 uint64_t _target_ea,
                                 int _target_param_pos,
                                 std::vector<hexrays_target_call_t> *_out)
      : ctree_visitor_t(CV_FAST),
        func(_func),
        target_ea(_target_ea),
        target_param_pos(_target_param_pos),
        out(_out) {}

  int idaapi visit_expr(cexpr_t *expr) override {
    if (expr != nullptr && expr->op == cot_call) {
      idalib_hexrays_collect_target_call_if_matches(func, expr, target_ea,
                                                    target_param_pos, out);
    }
    return 0;
  }
};

struct idalib_this_expr_collector_t : public ctree_visitor_t {
  const cfunc_t *func;
  const std::set<int> *aliases;
  std::vector<hexrays_this_expr_t> *out;

  idalib_this_expr_collector_t(const cfunc_t *_func,
                               const std::set<int> *_aliases,
                               std::vector<hexrays_this_expr_t> *_out)
      : ctree_visitor_t(CV_FAST), func(_func), aliases(_aliases), out(_out) {}

  int idaapi visit_expr(cexpr_t *expr) override {
    const cexpr_t *alias_expr = nullptr;
    int alias_idx = -1;
    if (expr == nullptr ||
        !idalib_hexrays_expr_find_alias_field_access(expr, aliases, &alias_expr, &alias_idx)) {
      return 0;
    }

    out->push_back(hexrays_this_expr_t{
        func->entry_ea,
        expr->ea,
        int32_t(expr->op),
        int32_t(alias_idx),
        rust::String(idalib_hexrays_op_name(expr->op)),
        idalib_hexrays_this_expr_kind(expr, aliases),
        idalib_hexrays_item_text(expr, func),
        alias_expr != nullptr ? idalib_hexrays_item_text(alias_expr, func) : rust::String(),
    });
    return 0;
  }
};

std::unique_ptr<hexrays_assignment_vec>
idalib_hexrays_cfunc_assignments(cfunc_t *f) {
  auto out = std::make_unique<hexrays_assignment_vec>();
  idalib_assignment_collector_t visitor(out.get());
  visitor.apply_to(&f->body, nullptr);
  return out;
}

std::unique_ptr<hexrays_call_edge_vec>
idalib_hexrays_cfunc_call_edges(cfunc_t *f, rust::Slice<const int32_t> aliases,
                                rust::Str kind) {
  auto out = std::make_unique<hexrays_call_edge_vec>();
  std::set<int> alias_set;
  for (int32_t alias : aliases) {
    alias_set.insert(alias);
  }
  std::string kind_string(kind);
  idalib_call_edge_collector_t visitor(f, &alias_set, kind_string.c_str(), out.get());
  visitor.apply_to(&f->body, nullptr);
  return out;
}

std::unique_ptr<hexrays_target_call_vec>
idalib_hexrays_cfunc_target_calls(cfunc_t *f, uint64_t target_ea,
                                  int32_t target_param_pos) {
  auto out = std::make_unique<hexrays_target_call_vec>();
  idalib_target_call_collector_t visitor(f, target_ea, target_param_pos, out.get());
  visitor.apply_to(&f->body, nullptr);
  return out;
}

std::unique_ptr<hexrays_this_expr_vec>
idalib_hexrays_cfunc_this_expressions(cfunc_t *f, rust::Slice<const int32_t> aliases) {
  auto out = std::make_unique<hexrays_this_expr_vec>();
  std::set<int> alias_set;
  for (int32_t alias : aliases) {
    alias_set.insert(alias);
  }
  idalib_this_expr_collector_t visitor(f, &alias_set, out.get());
  visitor.apply_to(&f->body, nullptr);
  return out;
}

std::size_t idalib_hexrays_assignments_len(
    const hexrays_assignment_vec &items) {
  return items.size();
}

hexrays_assignment_t idalib_hexrays_assignments_get(
    const hexrays_assignment_vec &items, std::size_t index) {
  return items.at(index);
}

std::size_t idalib_hexrays_call_edges_len(
    const hexrays_call_edge_vec &items) {
  return items.size();
}

hexrays_call_edge_t idalib_hexrays_call_edges_get(
    const hexrays_call_edge_vec &items, std::size_t index) {
  return items.at(index);
}

std::size_t idalib_hexrays_target_calls_len(
    const hexrays_target_call_vec &items) {
  return items.size();
}

hexrays_target_call_t idalib_hexrays_target_calls_get(
    const hexrays_target_call_vec &items, std::size_t index) {
  return items.at(index);
}

std::size_t idalib_hexrays_this_expressions_len(
    const hexrays_this_expr_vec &items) {
  return items.size();
}

hexrays_this_expr_t idalib_hexrays_this_expressions_get(
    const hexrays_this_expr_vec &items, std::size_t index) {
  return items.at(index);
}

hexrays_lvar_info_t idalib_hexrays_cfunc_lvar_info(
    cfunc_t *f, int32_t index) {
  lvars_t *lvars = f->get_lvars();
  if (lvars == nullptr || index < 0 || size_t(index) >= lvars->size()) {
    return hexrays_lvar_info_t{-1, rust::String(), rust::String(), false};
  }
  lvar_t &lvar = lvars->at(size_t(index));
  return hexrays_lvar_info_t{
      index,
      rust::String(lvar.name.c_str()),
      rust::String(lvar.type().dstr()),
      true,
  };
}

hexrays_lvar_info_t idalib_hexrays_cfunc_param_info(
    cfunc_t *f, int32_t param_pos) {
  if (param_pos < 0 || size_t(param_pos) >= f->argidx.size()) {
    return hexrays_lvar_info_t{-1, rust::String(), rust::String(), false};
  }
  return idalib_hexrays_cfunc_lvar_info(f, f->argidx[size_t(param_pos)]);
}

int32_t idalib_hexrays_cfunc_param_lvar_idx(cfunc_t *f, int32_t param_pos) {
  if (param_pos < 0 || size_t(param_pos) >= f->argidx.size()) {
    return -1;
  }
  return f->argidx[size_t(param_pos)];
}

std::unique_ptr<hexrays_i32_vec> idalib_hexrays_cfunc_alias_param_positions(
    cfunc_t *f, rust::Slice<const int32_t> aliases) {
  auto out = std::make_unique<hexrays_i32_vec>();
  std::set<int> alias_set;
  for (int32_t alias : aliases) {
    alias_set.insert(alias);
  }
  for (size_t pos = 0; pos < f->argidx.size(); pos++) {
    if (alias_set.find(f->argidx[pos]) != alias_set.end()) {
      out->push_back(int32_t(pos));
    }
  }
  return out;
}

std::size_t idalib_hexrays_i32_vec_len(const hexrays_i32_vec &items) {
  return items.size();
}

int32_t idalib_hexrays_i32_vec_get(const hexrays_i32_vec &items,
                                   std::size_t index) {
  return items.at(index);
}

bool idalib_hexrays_cfunc_apply_lvar_info(cfunc_t *f, int32_t lvar_idx,
                                          rust::Str name, rust::Str type_decl,
                                          bool persist) {
  lvars_t *lvars = f->get_lvars();
  if (lvars == nullptr || lvar_idx < 0 || size_t(lvar_idx) >= lvars->size()) {
    return false;
  }

  lvar_t &lvar = lvars->at(size_t(lvar_idx));
  bool changed = false;
  std::string name_string(name);
  if (!name_string.empty() && lvar.name != name_string.c_str()) {
    if (f->mba != nullptr && f->mba->set_nice_lvar_name(lvar, name_string.c_str())) {
      changed = true;
    } else {
      lvar.name = name_string.c_str();
      lvar.set_user_name();
      changed = true;
    }
  }

  tinfo_t tif;
  std::string type_string(type_decl);
  if (!type_string.empty() &&
      parse_decl(&tif, nullptr, get_idati(), type_string.c_str(), PT_SIL | PT_TYP | PT_SEMICOLON)) {
    if (lvar.set_lvar_type(tif, true)) {
      lvar.set_user_type();
      changed = true;
    }

    if (persist) {
      lvar_saved_info_t info;
      info.ll = lvar;
      info.name = name_string.c_str();
      info.type = tif;
      info.size = tif.get_size();
      if (modify_user_lvar_info(f->entry_ea, MLI_NAME | MLI_TYPE, info)) {
        changed = true;
      }
    }
  }

  if (changed) {
    f->refresh_func_ctext();
  }
  return changed;
}

bool idalib_hexrays_cfunc_apply_param_info(cfunc_t *f, int32_t param_pos,
                                           rust::Str name, rust::Str type_decl,
                                           bool persist) {
  int32_t lvar_idx = idalib_hexrays_cfunc_param_lvar_idx(f, param_pos);
  if (lvar_idx < 0) {
    return false;
  }
  return idalib_hexrays_cfunc_apply_lvar_info(f, lvar_idx, name, type_decl, persist);
}

int32_t idalib_parse_decls_file(rust::Str path) {
  std::string path_string(path);
  return parse_decls(get_idati(), path_string.c_str(), nullptr,
                     HTI_FIL | HTI_DCL | HTI_NDC);
}

bool idalib_named_type_exists(rust::Str name) {
  std::string name_string(name);
  tinfo_t tif;
  return tif.get_named_type(get_idati(), name_string.c_str());
}

bool idalib_save_database_with_backup() {
  return save_database(nullptr, DBFL_BAK);
}

cfunc_t *idalib_hexrays_cfuncptr_inner(const cfuncptr_t *f) { return *f; }

std::unique_ptr<cfuncptr_t>
idalib_hexrays_decompile_func(func_t *f, hexrays_error_t *err, int flags) {
  hexrays_failure_t failure;
  cfuncptr_t cf = decompile_func(f, &failure, flags);

  if (failure.code >= 0 && cf != nullptr) {
    return std::unique_ptr<cfuncptr_t>(new cfuncptr_t(cf));
  }

  err->code = failure.code;
  err->desc = rust::String(failure.desc().c_str());
  err->addr = failure.errea;

  return nullptr;
}

rust::String idalib_hexrays_cfunc_pseudocode(cfunc_t *f) {
  auto sv = f->get_pseudocode();
  auto sb = std::stringstream();

  auto buf = qstring();

  for (int i = 0; i < sv.size(); i++) {
    tag_remove(&buf, sv[i].line);
    sb << buf.c_str() << '\n';
  }

  return rust::String(sb.str());
}

std::unique_ptr<cblock_iter> idalib_hexrays_cblock_iter(cblock_t *b) {
  return std::unique_ptr<cblock_iter>(new cblock_iter(b));
}

cinsn_t *idalib_hexrays_cblock_iter_next(cblock_iter &it) {
  if (it.start != it.end) {
    return &*(it.start++);
  }
  return nullptr;
}

std::size_t idalib_hexrays_cblock_len(cblock_t *b) { return b->size(); }
