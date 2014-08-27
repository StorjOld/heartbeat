#include <Python.h>
#include <CXX/Objects.hxx>
#include <iostream>

static PyObject *
SwPriv_Test(PyObject *self, PyObject *args)
{
	std::cout << "Testing Shacham Waters Private HLA" << std::endl;
	
	Py_RETURN_NONE;
}

static struct PyMethodDef SwPrivMethods[] =
{
	{"Test",SwPriv_Test, METH_VARARGS, "Test Python Extensions"},
	{NULL,NULL,0,NULL}
};

static struct PyModuleDef SwPrivModule = 
{
	PyModuleDef_HEAD_INIT,
	"SwPriv",
	NULL,
	-1,
	SwPrivMethods
};

PyMODINIT_FUNC
PyInit_SwPriv(void)
{
	PyObject *m;
	
	m = PyModule_Create(&SwPrivModule);
	if (m == NULL)
		return NULL;
		
	return m;
}