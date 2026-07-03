#pragma once

#include "name.hpp"

#include <cstdint>

#include "cxx.h"

bool idalib_force_name(std::uint64_t ea, rust::Str name) {
  std::string name_string(name);
  return force_name(ea_t(ea), name_string.c_str(), SN_NOCHECK | SN_NOWARN);
}
