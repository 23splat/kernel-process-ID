UINT_PTR processid(PEPROCESS process)
{
	// checking if the arg passed is valid
	if (!process)
		return NULL;
	//querying the size of the information we want to read
	ULONG bytes = 0;
	NTSTATUS status = ZwQueryInformationProcess(ZwCurrentProcess(), ProcessBasicInformation, NULL, sizeof(NULL), &bytes);
	// checking if the size got updated
	if (!bytes)
		return NULL;
	// allocating memory the size of the information
	PPROCESS_BASIC_INFORMATION processinformation = (PPROCESS_BASIC_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x4e554c4c);
	// filling the allocated memory with the information
	// attaching to the target process so we can do so
	KAPC_STATE state;
	KeStackAttachProcess(process, &state);
	status = ZwQueryInformationProcess(ZwCurrentProcess(), ProcessBasicInformation, processinformation, sizeof(processinformation), &bytes);
	// checking the NTSTATUS code
	if (!NT_SUCCESS(status))
	{
		// if it failed, we will free the allocated memory, detach the thread from the target process and return
		KeUnstackDetachProcess(&state);
		ExFreePoolWithTag(processinformation, 0x4e554c4c);
		return NULL;
	}
	// now we just clean up and return the processID;
	KeUnstackDetachProcess(&state);
	ExFreePoolWithTag(processinformation, 0x4e554c4c);
	return processinformation->UniqueProcessId;
}
