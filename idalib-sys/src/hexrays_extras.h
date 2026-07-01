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

using hexrays_assignment_vec = std::vector<hexrays_assignment_t>;
using hexrays_call_edge_vec = std::vector<hexrays_call_edge_t>;
using hexrays_target_call_vec = std::vector<hexrays_target_call_t>;
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
