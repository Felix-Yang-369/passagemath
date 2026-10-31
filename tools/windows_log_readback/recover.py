from pathlib import Path
import argparse,sys
from protocol import MAX_INPUT_LOG_BYTES,RelayError,canonical,identity,recover_to,require

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source-job-id',type=int,required=True);parser.add_argument('relay_job_log',type=Path);parser.add_argument('fresh_output',type=Path);args=parser.parse_args()
    try:
        require(args.relay_job_log.stat().st_size<=MAX_INPUT_LOG_BYTES,'RELAY_INPUT_SIZE_LIMIT');result=recover_to(args.relay_job_log.read_bytes(),identity(args.source_job_id),args.fresh_output);print(canonical(result).decode('ascii'));return 0
    except RelayError as error:print(canonical({'recovery_complete':False,'error_type':error.code}).decode('ascii'));return 1
    except Exception as error:print(canonical({'recovery_complete':False,'error_type':type(error).__name__}).decode('ascii'));return 1

if __name__=='__main__':raise SystemExit(main())
