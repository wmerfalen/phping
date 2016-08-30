#include "ping.hpp"

/**
 * parameters: 
 * host
 * device
 * callback
 * count
 */
void ping(Php::Parameters &params){
    int ret = 0;
    Phping phping;
    phping.setDevice(params);
    //Params: host,callback,count
    ret = phping.ping(params);
    if(ret < 0){
        //Throw exception?
        //
    }

}


/**
 *  tell the compiler that the get_module is a pure C function
 */
extern "C" {
    
    /**
     *  Function that is called by PHP right after the PHP process
     *  has started, and that returns an address of an internal PHP
     *  strucure with all the details and features of your extension
     *
     *  @return void*   a pointer to an address that is understood by PHP
     */
    PHPCPP_EXPORT void *get_module() 
    {
        static Php::Extension extension("phping", "2.0");
        extension.add<ping>("ping",{
            Php::ByVal("host",Php::Type::String,true),
            Php::ByVal("device",Php::Type::String,true),
            Php::ByVal("callback",Php::Type::String,true),
            Php::ByVal("count",Php::Type::Numeric,false)
        });
		Php::Class<Phping> phping("Phping");
        phping.method<&Phping::getHost> ("getHost");
        phping.method<&Phping::getDestIp> ("getDestIp");
        phping.method<&Phping::getAvg>     ("getAvg");
        phping.method<&Phping::getErrorStr>     ("getErrorStr");
        phping.method<&Phping::setMaxResponses>     ("setMaxResponses");
        phping.method<&Phping::setDevice>     ("setDevice");
        phping.method<&Phping::ping>("ping");
        phping.method<&Phping::getSequenceNumber>("getSequenceNumber");
        phping.method<&Phping::setSequenceNumber>("setSequenceNumber");

        // add the class to the extension
        extension.add(std::move(phping));
        return extension;
    }
}

