/**
    printAllClasses() - Prints you all the classes loaded.
    findMethod(searchStr) - Finds you methods containing the searchStr.
    hookall(className, cb) - Hooks all methods in the class.
**/

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

function hookall(className, cb) {
    const cls = Java.use(className);
    const funcs = Object.getOwnPropertyNames(cls.$classWrapper.prototype);
    for (f in funcs) {
        try {
            var func_name = funcs[f];
            overloads = cls[func_name].overloads;
            for (i in overloads) {
                if (overloads[i].hasOwnProperty('argumentTypes')) {
                    console.log("Hooking class: " + className + " Function: " + func_name + "\n");
                    var parameters = [];
                    for (j in overloads[i].argumentTypes) {
                        parameters.push(overloads[i].argumentTypes[j].className);
                    }
                    const cb = getGenericInterceptor(className, func_name, parameters);
                    cls[func_name].overload.apply('this', parameters).implementation = cb;
                }
            }
        }   
        catch(e) {
            console.log("Failed hooking class: " + className + " Function: " + func_name + "\n");
        }
    }
}

function hook(className, func_name) {
    try {
        const cls = Java.use(className);
        overloads = cls[func_name].overloads;
        for (i in overloads) {
            if (overloads[i].hasOwnProperty('argumentTypes')) {
                console.log("Hooking class: " + className + " Function: " + func_name + "\n");
                var parameters = [];
                for (j in overloads[i].argumentTypes) {
                    parameters.push(overloads[i].argumentTypes[j].className);
                }
                const cb = getGenericInterceptor(className, func_name, parameters);
                cls[func_name].overload.apply('this', parameters).implementation = cb;
            }
        }
    }   
    catch(e) {
        console.log("Failed hooking class: " + className + " Function: " + func_name + "\n");
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

function printAllClasses() {
    Java.enumerateLoadedClasses({
        "onMatch": function(className) {
            console.log(className);           
        },
        "onComplete":function() {
        }
    });
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

if (Java.available) {
    // Switch to the Java context
    Java.perform(function() {
        //OTHERS_TO_ADD
        //CLASSES_TO_ADD
        //METHODS_TO_ADD
    });
}