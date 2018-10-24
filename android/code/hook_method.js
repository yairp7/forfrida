function hook(className, func_name, get_stacktrace) {
    try {
        const exceptionClass = Java.use('java.lang.Exception');
        const cls = Java.use(className);
        overloads = cls[func_name].overloads;
        for (i in overloads) {
            if (overloads[i].hasOwnProperty('argumentTypes')) {
                log_msg("Hooking class: " + className + " Function: " + func_name + (get_stacktrace ? '(with stacktrace)': '') + "\n");
                var parameters = [];
                for (j in overloads[i].argumentTypes) {
                    parameters.push(overloads[i].argumentTypes[j].className);
                }
                cls[func_name].overload.apply(cls[func_name], parameters).implementation = function () {
                    var args = [].slice.call(arguments);
                    var args2 = [];
                    for(var arg in args) {
                        args2.push(args[arg].toString());
                    }
                    args2 = args2.join(', ');
                    var result = this[func_name].apply(this, args); 
                    var resultString = result != null ? result.toString() : "No Result";
                    var argsString = (args2 != null && args2.length > 0) ? args2 : "";
                    if(get_stacktrace) {
                        var calledFrom = Exception.$new().getStackTrace().toString().split(',')[1];
                        log_event(className + '.' + func_name, argsString, resultString, calledFrom);
                    }
                    else {
                        log_event(className + '.' + func_name, argsString, resultString);
                    }
                    return result;
                }
            }
        }
    }   
    catch(e) {
        log_msg("Failed hooking class: " + className + " Function: " + func_name + "\n");
    }
}