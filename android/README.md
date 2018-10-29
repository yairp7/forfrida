## Android Hooking

Before:
- [iOS]`Start Cydia and add Frida’s repository by going to Manage -> Sources -> Edit -> Add and enter https://build.frida.re. You should now be able to find and install the Frida package which lets Frida inject JavaScript into apps running on your iOS device. This happens over USB, so you will need to have your USB cable handy, though there’s no need to plug it in just yet.`

Setup:
1) Clone the repository and `chmod +x python.py`
2) Attach the device(Android/iOS)

helper.py <android-app-package-name> OPTIONS
Options:
  -a => Print all classes
  -c <class1,class2,...> => Hook all methods in the provided classes
  -m <class1:method1,class2:method2,...> => Hook these specific methods
  -q => Quiet mode
  -o <output_file> => Writes output to file

example:
`./helper.py com.android.chrome -c package com.android.volley.toolbox.StringRequest -m java.lang.Throwable:toString,org.json.JSONObject:toString` - Hook all methods of StringRequest, and hook the specific methods of Throwable and JSONObject
