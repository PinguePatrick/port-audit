import unittest

from port_audit import audit, parse_netstat, parse_ss, parse_tasklist, render

NETSTAT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1100
  TCP    127.0.0.1:8765         0.0.0.0:0              LISTENING       4242
  TCP    127.0.0.1:8443         0.0.0.0:0              LISTENING       5151
  TCP    127.0.0.1:50000        127.0.0.1:8765         ESTABLISHED     9999
  TCP    [::]:135               [::]:0                 LISTENING       1100
"""

SS = 'LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=812,fd=3))\n' \
     'LISTEN 0      511        127.0.0.1:8080       0.0.0.0:*    users:(("java",pid=2020,fd=9))\n'

TASKLIST = '"svchost.exe","1100","Services","0","10,000 K"\n"python.exe","4242","Console","1","20,000 K"\n'

PLAN = {"range": [8000, 8999], "ports": {
    "135": {"name": "rpc", "process": "svchost.exe"},
    "8080": {"name": "app", "process": "java.exe"},
    "8765": {"name": "web", "process": "node.exe"},
}}


class ParseTests(unittest.TestCase):
    def test_netstat_keeps_only_listeners(self):
        live = parse_netstat(NETSTAT)
        self.assertEqual(sorted(live), [135, 8443, 8765])
        self.assertEqual(live[8765]["pid"], 4242)

    def test_ss(self):
        live = parse_ss(SS)
        self.assertEqual(live[22]["process"], "sshd")
        self.assertEqual(live[8080]["pid"], 2020)

    def test_tasklist(self):
        self.assertEqual(parse_tasklist(TASKLIST), {1100: "svchost.exe", 4242: "python.exe"})


class AuditTests(unittest.TestCase):
    def setUp(self):
        live = parse_netstat(NETSTAT)
        names = parse_tasklist(TASKLIST)
        for row in live.values():
            row["process"] = names.get(row["pid"])
        self.rows = {r["port"]: r for r in audit(PLAN, live)}

    def test_statuses(self):
        self.assertEqual(self.rows[135]["status"], "OK")
        self.assertEqual(self.rows[8080]["status"], "DOWN")
        self.assertEqual(self.rows[8765]["status"], "CONFLICT")
        self.assertEqual(self.rows[8443]["status"], "UNPLANNED")

    def test_out_of_range_listener_is_ignored(self):
        live = {50001: {"pid": 1, "address": "0.0.0.0", "process": "x"}}
        self.assertEqual(audit({"range": [8000, 8999], "ports": {}}, live), [])

    def test_render_has_summary(self):
        text = render(list(self.rows.values()))
        self.assertIn("CONFLICT 1", text)
        self.assertIn("UNPLANNED 1", text)


if __name__ == "__main__":
    unittest.main()
