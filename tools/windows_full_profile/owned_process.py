"""Run one owned Windows child tree inside a kill-on-close Job Object."""
import ctypes
from ctypes import wintypes as w
import subprocess
import time

k=ctypes.WinDLL('kernel32',use_last_error=True)
class IO(ctypes.Structure):
    _fields_=[(n,ctypes.c_ulonglong) for n in ('ReadOperationCount','WriteOperationCount','OtherOperationCount','ReadTransferCount','WriteTransferCount','OtherTransferCount')]
class Basic(ctypes.Structure):
    _fields_=[('PerProcessUserTimeLimit',ctypes.c_longlong),('PerJobUserTimeLimit',ctypes.c_longlong),('LimitFlags',w.DWORD),('MinimumWorkingSetSize',ctypes.c_size_t),('MaximumWorkingSetSize',ctypes.c_size_t),('ActiveProcessLimit',w.DWORD),('Affinity',ctypes.c_size_t),('PriorityClass',w.DWORD),('SchedulingClass',w.DWORD)]
class Extended(ctypes.Structure):
    _fields_=[('BasicLimitInformation',Basic),('IoInfo',IO),('ProcessMemoryLimit',ctypes.c_size_t),('JobMemoryLimit',ctypes.c_size_t),('PeakProcessMemoryUsed',ctypes.c_size_t),('PeakJobMemoryUsed',ctypes.c_size_t)]
k.CreateJobObjectW.argtypes=[ctypes.c_void_p,w.LPCWSTR];k.CreateJobObjectW.restype=w.HANDLE
k.SetInformationJobObject.argtypes=[w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD];k.SetInformationJobObject.restype=w.BOOL
k.AssignProcessToJobObject.argtypes=[w.HANDLE,w.HANDLE];k.AssignProcessToJobObject.restype=w.BOOL
k.QueryInformationJobObject.argtypes=[w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD,ctypes.POINTER(w.DWORD)];k.QueryInformationJobObject.restype=w.BOOL
k.TerminateJobObject.argtypes=[w.HANDLE,w.UINT];k.TerminateJobObject.restype=w.BOOL
k.CloseHandle.argtypes=[w.HANDLE];k.CloseHandle.restype=w.BOOL
k.TerminateProcess.argtypes=[w.HANDLE,w.UINT];k.TerminateProcess.restype=w.BOOL
class ThreadEntry(ctypes.Structure):
    _fields_=[('dwSize',w.DWORD),('cntUsage',w.DWORD),('th32ThreadID',w.DWORD),('th32OwnerProcessID',w.DWORD),('tpBasePri',w.LONG),('tpDeltaPri',w.LONG),('dwFlags',w.DWORD)]
k.CreateToolhelp32Snapshot.argtypes=[w.DWORD,w.DWORD];k.CreateToolhelp32Snapshot.restype=w.HANDLE
k.Thread32First.argtypes=[w.HANDLE,ctypes.POINTER(ThreadEntry)];k.Thread32First.restype=w.BOOL
k.Thread32Next.argtypes=[w.HANDLE,ctypes.POINTER(ThreadEntry)];k.Thread32Next.restype=w.BOOL
k.OpenThread.argtypes=[w.DWORD,w.BOOL,w.DWORD];k.OpenThread.restype=w.HANDLE
k.GetProcessIdOfThread.argtypes=[w.HANDLE];k.GetProcessIdOfThread.restype=w.DWORD
k.ResumeThread.argtypes=[w.HANDLE];k.ResumeThread.restype=w.DWORD

def pids(job):
    b=ctypes.create_string_buffer(65536);returned=w.DWORD()
    if not k.QueryInformationJobObject(job,3,b,len(b),ctypes.byref(returned)):
        raise ctypes.WinError(ctypes.get_last_error())
    count=ctypes.c_ulong.from_buffer(b,4).value
    return list((ctypes.c_size_t*count).from_buffer(b,8))

def resume_exact_primary_thread(process):
    snapshot=k.CreateToolhelp32Snapshot(4,0)  # TH32CS_SNAPTHREAD
    if not snapshot or int(snapshot)==ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    tids=[]
    try:
        entry=ThreadEntry();entry.dwSize=ctypes.sizeof(entry)
        ok=k.Thread32First(snapshot,ctypes.byref(entry))
        while ok:
            if entry.th32OwnerProcessID==process.pid:tids.append(entry.th32ThreadID)
            ok=k.Thread32Next(snapshot,ctypes.byref(entry))
    finally:k.CloseHandle(snapshot)
    if len(tids)!=1:raise RuntimeError({'suspended_process_thread_ids':tids,'pid':process.pid})
    thread=k.OpenThread(0x0002|0x0800,False,tids[0])  # SUSPEND_RESUME|QUERY_LIMITED_INFORMATION
    if not thread:raise ctypes.WinError(ctypes.get_last_error())
    try:
        actual_pid=k.GetProcessIdOfThread(thread)
        if actual_pid!=process.pid:raise RuntimeError({'thread_owner_mismatch':actual_pid,'expected':process.pid})
        count=k.ResumeThread(thread)
        if count!=1:raise RuntimeError({'unexpected_previous_suspend_count':count,'thread_id':tids[0]})
        return {'thread_id':tids[0],'confirmed_owner_pid':actual_pid,'previous_suspend_count':count}
    finally:k.CloseHandle(thread)

def run_tree(argv,*,cwd,env,stdout,stderr,timeout,on_start=None,force_assignment_failure=False):
    job=None
    process=None
    assigned=False
    result={'timed_out':False,'cleanup':[],'remaining_pids':None,'job_assignment':'not_started','creation_suspended':True,'actual_returncode':None}
    try:
        job=k.CreateJobObjectW(None,None)
        if not job:raise ctypes.WinError(ctypes.get_last_error())
        limits=Extended();limits.BasicLimitInformation.LimitFlags=0x2000
        if not k.SetInformationJobObject(job,9,ctypes.byref(limits),ctypes.sizeof(limits)):
            raise ctypes.WinError(ctypes.get_last_error())
        process=subprocess.Popen(argv,cwd=cwd,env=env,stdout=stdout,stderr=stderr,creationflags=0x00000004|subprocess.CREATE_NEW_PROCESS_GROUP)
        result['pid']=process.pid
        assignment_ok=False if force_assignment_failure else bool(k.AssignProcessToJobObject(job,w.HANDLE(int(process._handle))))
        if not assignment_ok:
            result['job_assignment']='failed'
            result['forced_assignment_failure_control']=force_assignment_failure
            raise RuntimeError({'job_assignment_error':ctypes.get_last_error(),'forced_control':force_assignment_failure})
        assigned=True
        result['job_assignment']='assigned'
        result['resume']=resume_exact_primary_thread(process)
        if on_start:on_start({'pid':process.pid,'job_assignment':'assigned','initial_pids':pids(job)})
        try:process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            result['timed_out']=True
            result['pids_at_timeout']=pids(job)
            ok=k.TerminateJobObject(job,0xEF)
            result['cleanup'].append({'method':'TerminateJobObject','succeeded':bool(ok),'winerror':ctypes.get_last_error() if not ok else 0})
            process.wait(timeout=15)
        result['actual_returncode']=process.returncode
    except Exception as error:
        result['error']={'type':type(error).__name__,'message':str(error)}
        if process is not None and process.poll() is None:
            if assigned:
                ok=k.TerminateJobObject(job,0xEE);method='exception_TerminateJobObject'
            else:
                # The primary thread has never resumed, so it cannot have children.
                ok=k.TerminateProcess(w.HANDLE(int(process._handle)),0xED);method='suspended_known_handle_TerminateProcess'
            result['cleanup'].append({'method':method,'succeeded':bool(ok),'winerror':ctypes.get_last_error() if not ok else 0})
            try:process.wait(timeout=15)
            except Exception as wait_error:result['cleanup_wait_error']=str(wait_error)
        if process is not None:result['actual_returncode']=process.poll()
    finally:
        if job:
            try:
                remaining=pids(job)
                deadline=time.monotonic()+5
                while remaining and time.monotonic()<deadline:
                    time.sleep(.05);remaining=pids(job)
                if remaining:
                    ok=k.TerminateJobObject(job,0xEC)
                    result['cleanup'].append({'method':'remaining_tree_cleanup','pids':remaining,'succeeded':bool(ok)})
                    deadline=time.monotonic()+5
                    while remaining and time.monotonic()<deadline:
                        time.sleep(.05);remaining=pids(job)
                result['remaining_pids']=remaining
            except Exception as query_error:result['remaining_query_error']=str(query_error)
            k.CloseHandle(job)
        elif process is None:result['remaining_pids']=[]
    return result
