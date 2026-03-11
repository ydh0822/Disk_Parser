find_path(TSK_INCLUDE_DIR NAMES tsk/libtsk.h)
find_library(TSK_LIBRARY NAMES tsk sleuthkit)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(TSK DEFAULT_MSG TSK_INCLUDE_DIR TSK_LIBRARY)

if(TSK_FOUND)
  add_library(TSK::tsk UNKNOWN IMPORTED)
  set_target_properties(TSK::tsk PROPERTIES
    IMPORTED_LOCATION "${TSK_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${TSK_INCLUDE_DIR}")
endif()
