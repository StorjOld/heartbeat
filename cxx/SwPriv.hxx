#pragma once

// must include cmath before python to avoid clash of hypot later.
#include <cmath>
#include <Python.h>
#include <CXX/Objects.hxx>
#include <CXX/Extensions.hxx>
#include <iostream>
#include "serializable.hxx"
#include "shacham_waters_private.hxx"
#include "PyBytesSink.hxx"

namespace SwPriv
{

// This encapsulates a wrapper class for a serializable class
template<typename T>
class PyBytesStateAccessible : public T
{
public:
	Py::Bytes get_state()
	{
		// serialize the underlying and output
		PyBytesSink sink;
		
		this->serialize(sink);
		
		return sink.finish();
	}
	
	void set_state(Py::Bytes state)
	{
		this->deserializep(new CryptoPP::StringSource(state,true));
	}
};

template<typename Tthis, typename Tbase>
class PyBytesStateAccessiblePyClass : public Py::PythonClass<Tthis>, public PyBytesStateAccessible<Tbase>
{
public:
	typedef PyBytesStateAccessiblePyClass<Tthis,Tbase> this_type;

	PyBytesStateAccessiblePyClass( Py::PythonClassInstance *self, Py::Tuple &args, Py::Dict &kwds )
		: Py::PythonClass< Tthis >::PythonClass( self, args, kwds ) 
	{
		std::cout << "PyBytesStateAccessiblePyClass<Tthis,Tbase> constructor called." << std::endl;
	}

	static void init_type_dont_ready(std::string T_type_name)
	{
		Tthis::behaviors().name(T_type_name.c_str());
		// documentation?
        Tthis::behaviors().supportGetattro();
        Tthis::behaviors().supportSetattro();
		
		Tthis::PYCXX_ADD_NOARGS_METHOD( __getstate, _get_state, "doc: get_state()" );
		Tthis::PYCXX_ADD_VARARGS_METHOD(  __setstate__, _set_state, "doc: set_state( state )");
	}
	
	static void init_type(std::string T_type_name)
	{
		init_type_dont_ready(T_type_name);
		
		Tthis::behaviors.readyType();
	}
	
	Py::Object getattro( const Py::String &name_ )
    {
        return this->genericGetAttro( name_ );
    }
	
	int setattro( const Py::String &name_, const Py::Object &value )
    {
        return this->genericSetAttro( name_, value );
    }
	
	Py::Object _get_state()
	{
		return this->get_state();
	}
	PYCXX_NOARGS_METHOD_DECL( Tthis, _get_state )
	
	Py::Object _set_state(const Py::Tuple &args )
	{
		if (args.length() != 1)
		{
			throw Py::RuntimeError("set_state only takes one argument: state");
		}
		
		this->set_state(args[0]);
		
		return Py::None();
	}
	PYCXX_VARARGS_METHOD_DECL( Tthis, _set_state )
};

class Tag : public PyBytesStateAccessiblePyClass<Tag,shacham_waters_private_data::tag>
{
public:
	Tag( Py::PythonClassInstance *self, Py::Tuple &args, Py::Dict &kwds )
		: PyBytesStateAccessiblePyClass<Tag,shacham_waters_private_data::tag>(self,args,kwds) 
	{
	}
	
	static void init_type()
	{
		PyBytesStateAccessiblePyClass<Tag,shacham_waters_private_data::tag>::init_type_dont_ready("Tag");
		
		behaviors().readyType();
	}
};

class State : public PyBytesStateAccessiblePyClass<State,shacham_waters_private_data::state>
{
public:
	State( Py::PythonClassInstance *self, Py::Tuple &args, Py::Dict &kwds )
		: PyBytesStateAccessiblePyClass<State,shacham_waters_private_data::state>(self,args,kwds) 
	{
	}
	
	static void init_type()
	{
		PyBytesStateAccessiblePyClass<State,shacham_waters_private_data::state>::init_type_dont_ready("State");
		
		behaviors().readyType();
	}
};

class Challenge : public PyBytesStateAccessiblePyClass<Challenge,shacham_waters_private_data::challenge>
{
public:
	Challenge( Py::PythonClassInstance *self, Py::Tuple &args, Py::Dict &kwds )
		: PyBytesStateAccessiblePyClass<Challenge,shacham_waters_private_data::challenge>(self,args,kwds) 
	{
	}
	
	static void init_type()
	{
		PyBytesStateAccessiblePyClass<Challenge,shacham_waters_private_data::challenge>::init_type_dont_ready("Challenge");
		
		behaviors().readyType();
	}
};

class Proof : public PyBytesStateAccessiblePyClass<Proof,shacham_waters_private_data::proof>
{
public:
	Proof( Py::PythonClassInstance *self, Py::Tuple &args, Py::Dict &kwds )
		: PyBytesStateAccessiblePyClass<Proof,shacham_waters_private_data::proof>(self,args,kwds) 
	{
	}
	
	static void init_type()
	{
		PyBytesStateAccessiblePyClass<Proof,shacham_waters_private_data::proof>::init_type_dont_ready("Proof");
		
		behaviors().readyType();
	}
};


class SwPriv : public PyBytesStateAccessiblePyClass<SwPriv,shacham_waters_private>
{
public:
	SwPriv( Py::PythonClassInstance *self, Py::Tuple &args, Py::Dict &kwds )
		: PyBytesStateAccessiblePyClass<SwPriv,shacham_waters_private>(self,args,kwds) 
	{
		std::cout << "SwPriv constructor called..." << std::endl;
	}

	static void init_type()
	{
		PyBytesStateAccessiblePyClass<SwPriv,shacham_waters_private>::init_type_dont_ready("SwPriv");
		
		PYCXX_ADD_NOARGS_METHOD( gen, _gen, "doc: gen()" );
		PYCXX_ADD_NOARGS_METHOD( get_public, _get_public, "doc: get_public()" );
		PYCXX_ADD_VARARGS_METHOD( encode, _encode, "doc: (tag,state) = encode(file)" );
		PYCXX_ADD_VARARGS_METHOD( gen_challenge, _gen_challenge, "doc: challenge = gen_challenge(state)" );
		PYCXX_ADD_VARARGS_METHOD( prove, _prove, "doc: proof = prove(file,challenge,tag)" );
		PYCXX_ADD_VARARGS_METHOD( verify, _verify, "doc: is_valid = verify(proof,challenge,state)" );
		
		behaviors().readyType();
	}
	
	Py::Object _gen()
	{
		gen();
		
		std::cout << "heartbeat generated." << std::endl;
		
		return Py::None();
	}
	PYCXX_NOARGS_METHOD_DECL( SwPriv, _gen )
	
	Py::Object _get_public()
	{
		Py::Callable class_type( SwPriv::type() );
        Py::PythonClassObject<SwPriv> pyobj( class_type.apply( Py::Tuple() ) );
		SwPriv *obj = pyobj.getCxxObject();
		
		get_public(*obj);
		
		return pyobj;
	}
	PYCXX_NOARGS_METHOD_DECL( SwPriv, _get_public )
	
	Py::Object _encode(const Py::Tuple &args )
	{
		Py::Callable tag_type( Tag::type() );
		Py::PythonClassObject<Tag> tag_pyobj( class_type.apply( Py::Tuple() ) );
	}
	PYCXX_VARARGS_METHOD_DECL( SwPriv, _encode )
	
	Py::Object _gen_challenge(const Py::Tuple &args )
	{
		throw Py::RuntimeError("Not implemented");
	}
	PYCXX_VARARGS_METHOD_DECL( SwPriv, _gen_challenge )
	
	Py::Object _prove(const Py::Tuple &args )
	{
		throw Py::RuntimeError("Not implemented");
	}
	PYCXX_VARARGS_METHOD_DECL( SwPriv, _prove )
	
	Py::Object _verify(const Py::Tuple &args )
	{
		throw Py::RuntimeError("Not implemented");
	}
	PYCXX_VARARGS_METHOD_DECL( SwPriv, _verify )
};

}

class Module : public Py::ExtensionModule<Module>
{
public:
	Module()
		: Py::ExtensionModule<Module>("SwPriv")
	{
		SwPriv::SwPriv::init_type();
		
		initialize("Documentation for Private HLA Module");
		
		Py::Dict d( moduleDictionary() );
		Py::Object x( SwPriv::SwPriv::type() );
		d["SwPriv"] = x;
	}
};