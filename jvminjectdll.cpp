// based on code from http://www.marco-maniscalco.de/?p=388 and https://xantorohara.blogspot.co.nz/2007/09/java-code-injection-via-winapis.html
#include <windows.h>
#include <jni.h>
#include <jvmti.h>
#include "insider.h"

#include <string>
#include <iostream>
#include <fstream>
using namespace std;

char DUMP_DIRECTORY[1024];

static jrawMonitorID mutex;


static void check(jvmtiEnv *jvmti, jvmtiError errnum, const char *str)
{
	if (errnum != JVMTI_ERROR_NONE) {
		char *errnum_str = NULL;
		jvmti->GetErrorName(errnum, &errnum_str);
		char b[1024];
		sprintf_s(b, 1024, "ERROR: JVMTI: %d(%s): %s\n", errnum,
			(errnum_str == NULL ? "Unknown" : errnum_str),
			(str == NULL ? "" : str));
		MessageBoxA(0, b, "Error", MB_OK);
	}
}


static void enter_critical_section(jvmtiEnv *jvmti)
{
	jvmtiError error = jvmti->RawMonitorEnter(mutex);
	check(jvmti, error, "Cannot enter with raw monitor");
}


static void exit_critical_section(jvmtiEnv *jvmti)
{
	jvmtiError error = jvmti->RawMonitorExit(mutex);
	check(jvmti, error, "Cannot exit with raw monitor");
}


static void JNICALL loadClass(jvmtiEnv *jvmti,
	JNIEnv* env,
	jclass class_being_redefined,
	jobject loader,
	const char* name,
	jobject protection_domain,
	jint class_data_len,
	const unsigned char* class_data,
	jint* new_class_data_len,
	unsigned char** new_class_data)
{
	enter_critical_section(jvmti); {

		std::string str(name);
		for (int i = 0; i<str.length(); i++)
		{
			if (str[i] == '/')
				str[i] = '.';
		}

		char file[512] = "";
		sprintf_s(file, 512, "%s%s.class", DUMP_DIRECTORY, str.c_str());

		ofstream myfile;
		myfile.open(file);
		for (int i = 0; i<class_data_len; i++)
			myfile << class_data[i];
		myfile.close();

	} exit_critical_section(jvmti);
}


BOOL APIENTRY
DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{

		char* dumpdir = "dump\\";
		char b[1024];
		if (GetModuleFileNameA(NULL, DUMP_DIRECTORY, 1023) > 0) {
			char* x = NULL;
			for (x = DUMP_DIRECTORY + strlen(DUMP_DIRECTORY) - 1; x != DUMP_DIRECTORY && *x != '\\'; --x);
			x++;
			*x = '\0';
			strncat_s(DUMP_DIRECTORY, 1023, dumpdir, strlen(dumpdir));
		}
		if (!(CreateDirectoryA(DUMP_DIRECTORY, NULL) ||
			ERROR_ALREADY_EXISTS == GetLastError()))
		{
		
			sprintf_s(b, 1023, "Could not create dump directory %s for dumping. Perhaps it's not writable or path is too long?", DUMP_DIRECTORY);
			MessageBoxA(NULL, b, "Insider", MB_ICONERROR);
			return FALSE;
		}

		
//		sprintf_s(b, 1023, "Created %s", DUMP_DIRECTORY);
//		MessageBoxA(NULL, b, "Insider",
//			MB_OK);

		JavaVM *vmBuf;
		JNIEnv *env;
		jsize nVMs;
		jint res = 0;
		jclass resjclass = NULL;
		try
		{
			res = JNI_GetCreatedJavaVMs(&vmBuf, 1, &nVMs);
			if (res != JNI_OK || nVMs < 1)
			{
				MessageBoxA(NULL, "JVMs not found", "Insider", MB_ICONERROR);
				return FALSE;
			}

		}
		catch (...)
		{
			MessageBoxA(NULL, "Exception:JNI_GetCreatedJavaVMs", "Insider",
				MB_ICONERROR);
			return FALSE;
		}



		try
		{
			res = vmBuf[0].AttachCurrentThread((void **)&env, NULL);
			if (res != JNI_OK)
			{
				MessageBoxA(NULL, "Can't attach to JVM", "Insider", MB_ICONERROR);
				return FALSE;
			}
		}
		catch (...)
		{
			MessageBoxA(NULL, "Exception:AttachCurrentThread", "Insider", MB_ICONERROR);
			return FALSE;
		}


		JavaVM* vm = vmBuf;

		jint rc;
		jvmtiCapabilities capabilities;
		jvmtiEventCallbacks callbacks;
		jvmtiEnv *jvmti;
		rc = vmBuf[0].GetEnv((void **)&jvmti, JVMTI_VERSION);


		if (rc != JNI_OK) {
			sprintf_s(b, 1023, "ERROR: Unable to create jvmtiEnv, GetEnv failed, error=%d\n", rc);

			MessageBoxA(NULL, b, "Insider",
				MB_OK);
			return FALSE;

		} else {

			(jvmti)->GetCapabilities(&capabilities);
			capabilities.can_tag_objects = 1;
			capabilities.can_generate_garbage_collection_events = 1;
			capabilities.can_redefine_any_class = 1;
			capabilities.can_redefine_classes = 1;
			capabilities.can_generate_all_class_hook_events = 1;
			(jvmti)->AddCapabilities(&capabilities);


			(void)memset(&callbacks, 0, sizeof(callbacks));
			callbacks.ClassFileLoadHook = &loadClass;

			jvmtiError error = jvmti->SetEventCallbacks(&callbacks, (jint)sizeof(callbacks));
			check(jvmti, error, "Cannot set callbacks");

			error = jvmti->SetEventNotificationMode(JVMTI_ENABLE,
				JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, (jthread)NULL);
			check(jvmti, error, "Cannot set event notification");

			error = jvmti->CreateRawMonitor("agent data", &mutex);
			check(jvmti, error, "Cannot create raw monitor");

		}

	}

	return TRUE;
}
