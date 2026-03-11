find_path(LIBEWF_INCLUDE_DIR NAMES libewf.h)
find_library(LIBEWF_LIBRARY NAMES ewf libewf)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LIBEWF DEFAULT_MSG LIBEWF_INCLUDE_DIR LIBEWF_LIBRARY)

if(LIBEWF_FOUND)
  add_library(LIBEWF::libewf UNKNOWN IMPORTED)
  set_target_properties(LIBEWF::libewf PROPERTIES
    IMPORTED_LOCATION "${LIBEWF_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBEWF_INCLUDE_DIR}")
endif()
