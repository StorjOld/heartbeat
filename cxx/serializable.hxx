#include <cryptopp/filters.h>

class serializable
{
public:
	virtual void serialize(CryptoPP::BufferedTransformation &bt) const = 0;
	virtual void deserialize(CryptoPP::BufferedTransformation &bt) = 0;
	
	virtual void serializep(CryptoPP::BufferedTransformation *bt) const
	{
		serialize(*bt);
		delete bt;
	}
	
	virtual void deserializep(CryptoPP::BufferedTransformation *bt)
	{
		deserialize(*bt);
		delete bt;
	}
};