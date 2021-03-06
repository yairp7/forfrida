/**
    Code Template
*/

function log_msg(msg) {
    var obj = {
        "msg":msg
    };
    send(obj);
}

function log_event(source, args, result) {
    var obj = {
        "source":source,
        "args":args,
        "result":result
    };
    send(obj);
}

function send_command(cmd, params) {
    var obj = {
        "command":cmd,
        "params":params
    };
    send(obj);
}

function getGenericInterceptor(className, func, parameters, description) {
    args = []
    for (i = 0; i < parameters.length; i++) { 
            args.push('arg_' + i) 
    }
    var script = "result = this.__FUNCNAME__(__SEPARATED_ARG_NAMES__);\nlogmessage = '__CLASSNAME__.__FUNCNAME__(' + __SEPARATED_ARG_NAMES__ + ')__DESCRIPTION__ => ' + result;\nconsole.log(logmessage);\nreturn result;"
    
    script = script.replace(/__FUNCNAME__/g, func);
    script = script.replace(/__SEPARATED_ARG_NAMES__/g, args.join(', '));
    script = script.replace(/__CLASSNAME__/g, className);
    if(!description) {
        description = '';
    }
    else {
        description = '[' + description + ']';
    }
    script = script.replace(/__DESCRIPTION__/g, description);
    script = script.replace(/\+  \+/g, '+');

    args.push(script)
    cb = Function.apply(null, args)
    return cb
}

function hook_overloaded_method(obj, func, args, modify_args, filter, success) {
    try 
    {
        // var Exception = Java.use('java.lang.Exception'); 
        Java.use(obj)[func].overload.apply(Java.use(obj)[func], args).implementation = function () 
        {
            var args = [].slice.call(arguments);
            var args2 = [];
            for(var arg in args) {
                args2.push(args[arg].toString());
            }
            args2 = args2.join(', ');
            if(modify_args) {
                args = modify_args(args)
            }
            var result = this[func].apply(this, args); 
            // var calledFrom = Exception.$new().getStackTrace().toString().split(',')[1];
            var resultString = result != null ? result.toString() : "No Result";
            if((filter && filter(args, resultString)) || !filter) {
                var message = JSON.stringify(
                { 
                    function: obj + "." + func, 
                    arguments: (args2 != null && args2.length > 0) ? args2 : "No Arguments",
                    result: resultString,
                    // calledFrom: calledFrom
                });            
                // console.log(message);
            }
            return result;
        } 

        success();
    }
    catch (err) {
        console.log(obj + "." + func + "[\"Error\"] => " + err);
    }
}

function findMethod(searchStr) {
    Java.enumerateLoadedClasses({
        "onMatch": function(className) {
            try { 
                var cls = Java.use(className);
                var funcs = Object.getOwnPropertyNames(cls.$classWrapper.prototype);
                for (f in funcs) {
                    var func = funcs[f];
                    if(func.toLowerCase().indexOf(searchStr) >= 0) {
                        console.log("Found: " + func + " in " + className + "\n");
                    } 
                }
            }    
            catch(e) {
                    // console.log(e.message + "\n");
            }     
        },
        "onComplete":function() {
        }
    });
}

if (Java.available) {
    // Switch to the Java context
    Java.perform(function() {
        //OTHERS_TO_ADD
        //CLASSES_TO_ADD
        //METHODS_TO_ADD
        // send_command('finish', [1]);
    });
}