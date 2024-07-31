#include "other shit.hpp"


NTSTATUS DriverEntry(PDRIVER_OBJECT ob, PUNICODE_STRING rp) {
	UNREFERENCED_PARAMETER(rp);
	UNREFERENCED_PARAMETER(ob);
	return IoCreateDriver(NULL, &driverinit);
}

