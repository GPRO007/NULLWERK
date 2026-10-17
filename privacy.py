"""Make exported diagnostics path-free by default; no telemetry."""
import copy
import re


def public_report(report, include_paths=False):
    result=copy.deepcopy(report)
    if include_paths:
        result['privacy']='Includes local paths; review before sharing.'
        return result
    result['file']='input.exe'
    result['filename']='input.exe'
    operation=result.get('operation')
    if operation:
        operation['output']='output.exe'
    # Parser diagnostics are intentionally limited to application-generated text;
    # replace path-looking substrings in any future free-text diagnostics too.
    def scrub(value):
        if isinstance(value,str):
            value=re.sub(r'[A-Za-z]:[\\/][^\r\n\t\"]+', '[local path]', value)
            return value
        if isinstance(value,list):return [scrub(v) for v in value]
        if isinstance(value,dict):
            private_keys={'file':'input.exe','filename':'input.exe','folder':'[local folder]',
                          'original_file':'original.exe','modified_file':'modified.exe',
                          'relative_path':'[local input]','output':'output.exe'}
            return {k:(private_keys[k] if k in private_keys and isinstance(v,str) else scrub(v)) for k,v in value.items()}
        return value
    result=scrub(result)
    result['privacy']='Local input/output paths and filenames omitted. File hashes and import names remain.'
    return result
