/** Hook a single method inside a class **/
function observeFunction(class_name, func_name) {
    try {
        var c = ObjC.classes[class_name];
        var impl = c[func_name].implementation;
        console.log('Observing ' + class_name + ' ' + func_name);
        Interceptor.attach(impl, {
            onEnter: function(a) {
                this.log = [];
                this.log.push('(' + a[0] + ',' + Memory.readUtf8String(a[1]) + ') ' + class_name + ' ' + func_name);
                if (func_name.indexOf(':') !== -1) {
                    this.log.push("Has Parameters \n");
                    var params = func_name.split(':');

                    params[0] = params[0].split(' ')[1];
                    for (var i = 0; i < params.length - 1; i++) {
                        try {
                            this.log.push(params[i] + ': ' + new ObjC.Object(a[2 + i]).toString());
                        } catch (e) {
                            this.log.push(params[i] + ': ' + a[2 + i].toString());
                        }
                    }
                }

                this.log.push(
                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress)
                        .join('\n')
                );
            },

            onLeave: function(r) {
                try {
                    this.log.push('RET: ' + new ObjC.Object(r).toString());
                } catch (e) {
                    this.log.push('RET: ' + r.toString());
                }

                console.log(this.log.join('\n') + '\n');
            }
        });
    }
    catch(err) {
        console.log("ERR: \n" + err.message + '\n');
    }
}

/** Hook all methods inside a class **/
function observeClass(name) {
    try {
        var k = ObjC.classes[name];
        k.$ownMethods.forEach(function(m) {
            var impl = k[m].implementation;
            console.log('Observing ' + name + ' ' + m);
            Interceptor.attach(impl, {
                onEnter: function(a) {
                    this.log = [];
                    this.log.push('(' + a[0] + ',' + Memory.readUtf8String(a[1]) + ') ' + name + ' ' + m);
                    if (m.indexOf(':') !== -1) {
                        var params = m.split(':');
                        params[0] = params[0].split(' ')[1];
                        for (var i = 0; i < params.length - 1; i++) {
                            try {
                                this.log.push("a)" + params[i] + ': ' + new ObjC.Object(a[2 + i]).toString());
                            } catch (e) {
                                this.log.push("b)" + params[i] + ': ' + a[2 + i].toString());
                            }
                        }
                    }
                },
                onLeave: function(r) {
                    try {
                        this.log.push('RET: ' + new ObjC.Object(r).toString());
                    } catch (e) {
                        this.log.push('eRET: ' + r.toString());
                    }

                    console.log(this.log.join('\n') + '\n');
                }
            });
        });
    }
    catch(err) {
        console.log("ERR: \n" + err.message + '\n');
    }
}

var class_to_hook = "NSURLRequest";
observeClass(class_to_hook);