function printAllClasses() {
    Java.enumerateLoadedClasses({
        "onMatch": function(className) {
        	obj = { 'msg' : className }
            send(obj);           
        },
        "onComplete":function() {
        }
    });
}