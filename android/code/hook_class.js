function hookall(className, cb) {
    const cls = Java.use(className);
    const funcs = Object.getOwnPropertyNames(cls.$classWrapper.prototype);
    for (f in funcs) {
        try {
            var func_name = funcs[f];
            overloads = cls[func_name].overloads;
            for (i in overloads) {
                if (overloads[i].hasOwnProperty('argumentTypes')) {
                    log_msg("Hooking class: " + className + " Function: " + func_name + "\n");
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
            console.log_msg("Failed hooking class: " + className + " Function: " + func_name + "\n");
        }
    }
}