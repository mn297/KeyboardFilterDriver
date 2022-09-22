# Writing a Keyboard Filter - Driver by Vijay Mukhi #

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


The program y.c has no changes at all. Each time we start a new chapter we simply repeat the y.c program even though it has not changed since the last chapter. The program r.c is however totally different. Each time you press the A key from the keyboard in any application, the key s is shown instead. How this magic happens is what this chapter is all about.

Lets start with the DriverEntry program. We set the MajorFunction Read member to the function `abcRead`. For the nosy ones out there, the macro `IRP_MJ_READ` has a value of 3. Thus each time a read request is send to our driver, the function `abcRead` gets called. The read request in our case will be send when we press a key on the keyboard.

The IoCreateDevice function is always used to create a named device. In this case we specify null as our device name. The fourth parameter is the device type. This parameter tells the system on what type of device we would like to model our driver on.

Normally we specify either 0, `FILE_DEVICE_UNKNOWN` or a number that we create bearing in mind that  Microsoft has reserved the first 32767 numbers for themselves. The value of  the macro `FILE_DEVICE_KEYBOARD` is `0xb`. The rest of the parameters are what they always have been and the last is the address of  the device object that just got created. We are modeling ourselves on a keyboard driver. 

The only field of the `DEVICE_OBJECT` structure we set is Flags. There are lots of options here. We only set one bit DO_BUFFERED_IO. This flag determines how the I/O manager deals with user buffers when it transfers data to the driver. The other value that can be used is non buffer or DO_DIRECT_IO which as the name suggests does not use any buffers at all. 

The driver we create is called a filter driver. We are sitting above the keyboard driver. Thus each time we press a key we get called first, then we pass the request on to the lower driver. This could be the actual keyboard driver or another filter driver. When the lowest level driver handles the request, it gets send up all the way and once again our driver code gets called.

 

Thus we get called twice, Once in the beginning, once on the way back up. We have to set the Flags field so that it contains the same Flags as the driver below us. We all have to share the same flags or else we get a Blue Screen of Death. It does not make sense for us to use Direct_IO and the lower level driver uses Buffering.

As the actual keyboard driver uses buffering, we use buffering also. Now we need to tell the system, to actually put us into the keyboard loop. Each time a key is pressed our code  in this case the function abcRead. We first create a `UNICODE_STRING` for the keyboard driver whose name is `KeyboardClass0`.

We then use the IoAttachDevice which attaches our device that we specify as the first parameter pgenericdevice, the driver object that we created. The second parameter is the name of the device to attach to the keyboard device. The last is a pointer to a `DEVICE_OBJECT` that this function will initialize. It is this pointer that represents the attachment to keyboard driver.

To create a filter driver we have to follow a two stage process. We first create a device and attach this device to the keyboard driver.

The attachment of our driver is at the top of all the existing drivers for the keyboard. Now each time we press a key on the keyboard the abcRead function gets called. We receive a Interrupt Request Packet or IRP which is the heart of passing stuff from one device driver to another.

This structure IRP is extremely large and we will study it in detail. The IRP that we get we need to pass it on to the next lower down driver. This is like a 4 x 100 meter race. Each runner has to pass the baton to the next.

Thus we use a function that has a very large name IoCopyCurrentIrpStackLocationToNext which copies the IRP passed to us to a area of memory which the driver below us will read when it is called after we finish. Thus in the abcRead function we first need to pass the IRP to the next driver.

When the abcRead function is called the IRP is being passed down the line. They could be 10 filter drivers between us and the final keyboard driver. Thus as of now the actual keyboard driver has not been called. After it gets called, the whole process will repeat and the IRP will now move up instead of down.

When the IRP is moving up, the system will need to call a function in us. This function name we specify using the function `IoSetCompletionRoutine`. The first parameter is the all important IRP, the second is the name of the function to be called, abcReadOver, the third is the address of any parameters that we want passed to the function.

The last three we will explain a little later. By calling this function, we know that when the abcReadOver function gets called the keyboard request has been handled by the keyboard driver and the filter drivers sitting above the keyboard driver are now being called.

We increase a variable `numPendingIrps` by 1 as the IRP has not yet got over, it fact it has only started. We now need to actually call the next driver in the chain and we do this be using the function IoCallDriver. We pass the actual keyboard device object and not the generic device object.

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
