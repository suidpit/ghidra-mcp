f = currentProgram.getFunctionManager().getFunctionAt(currentAddress)

print(f"Exporting function {f.getName()} to frida snippet 🧙🏻‍♂️")

sig = f.getSignature()
retType = sig.getReturnType()
args = sig.getArguments()

print(f"""
Interceptor.attach(main.base.add(0x{f.getEntryPoint().toString()}), {{
    onEnter: function(args) {{
        console.log("----------------------------------------");
        console.log("[+] Entering {f.getName()}");
        {'\n'.join([f"console.log('{arg.name} ({arg.dataType}) = ' + args[{i}]);" for i, arg in enumerate(args)])}
    }},
    onLeave: function(retval) {{
        console.log("[+] Return value ({retType}) = " + retval);
        console.log("----------------------------------------");
    }}
}});
""")