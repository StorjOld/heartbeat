#include "SwPriv.hxx"
#include <Python.h>
#include <CXX/Objects.hxx>
#include <iostream>
 

extern "C" PyObject *PyInit_SwPriv()
{
	static Module* module = new Module;
	return module->module().ptr();
}