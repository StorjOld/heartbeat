#pragma once

#if PY_MAJOR_VERSION == 2

typedef Py::String py_array;
#define py_from_string_and_size PyString_FromStringAndSize
#define py_get_size PyString_GET_SIZE
#define py_resize _PyString_Resize
#define py_as_string_and_size PyString_AsStringAndSize

#else

typedef Py::Bytes py_array;
#define py_from_string_and_size PyBytes_FromStringAndSize
#define py_get_size PyBytes_GET_SIZE
#define py_resize _PyBytes_Resize
#define py_as_string_and_size PyBytes_AsStringAndSize

#endif
