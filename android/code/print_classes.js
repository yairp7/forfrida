function printAllClasses() {
    Java.enumerateLoadedClasses({
        "onMatch": function(className) {
            console.log(className);           
        },
        "onComplete":function() {
        }
    });
}