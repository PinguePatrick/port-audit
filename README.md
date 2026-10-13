# port-audit

Compare a declared port plan with what is really listening on a machine.
Read-only: it runs `netstat` and `tasklist` on Windows, or `ss` on Linux, and
changes nothing.

Standard library only.

## Why it matters for IT operations

"Is the service up?" and "what is listening on this port?" are two of the most
common support questions. This tool answers both against a written plan:

| Status | Meaning |
|---|---|
| `OK` | The planned port is listening (and the process name matches, when the plan names one). |
| `DOWN` | The plan says something should listen here, but nothing does. |
| `CONFLICT` | Something is listening, but it is not the process the plan expects. |
| `UNPLANNED` | A listener inside the managed range that is not in the plan. Worth a look: a stray dev server, a duplicate instance, or something that should not be there. |

The exit code is `1` when anything is not `OK`, so it can run from Task
Scheduler or cron and alert on failure.

## Run

```text
python port_audit.py --plan ports.example.json
python port_audit.py --plan ports.example.json --json
```

Plan (`ports.example.json`). `range` is the band of ports you manage; listeners
outside it are ignored unless they are in the plan:

```json
{
  "range": [8000, 8999],
  "ports": {
    "135": {"name": "rpc-endpoint", "process": "svchost.exe"},
    "445": {"name": "smb", "process": "System"},
    "8080": {"name": "intranet-app", "process": "java.exe"},
    "8765": {"name": "demo-web", "process": "python.exe"}
  }
}
```

## Sample output

A real run on Windows 11, with a demo web server on 8765 and a second,
unplanned one on 8443:

```text
> python port_audit.py --plan ports.example.json
  PORT  STATUS     NAME                  PID  PROCESS
   135  OK         rpc-endpoint         2304  svchost.exe
   445  OK         smb                     4  System
  8080  DOWN       intranet-app            -  -
  8765  OK         demo-web            52164  python.exe
  8443  UNPLANNED                      14012  python.exe
summary: DOWN 1, OK 3, UNPLANNED 1
```

## Tests

```text
> python -m unittest -v test_port_audit
Ran 6 tests in 0.000s
OK
```

The tests feed canned `netstat`, `ss` and `tasklist` output, so they run the
same on any machine.

## License

MIT
