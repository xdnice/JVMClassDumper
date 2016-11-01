# JVMClassDumper
This simple DLL injector hooks a running Java Virtual Machine's ClassLoader. Specifically it hooks the defineClass() method. It produces a dump of all classfiles loaded by the JVM from the point in time the hook is attached. The dumped classes are written to the location of the <jvm process's executable's directory>/dump/
