"""Exercise every directory read drs makes, with its own configuration and
account, against the configured DCs: run it after deploying, as the drs user.

HOW TO RUN: runuser -u drs -- python3 /opt/drs/deploy/check-directory.py /etc/drs/<instance>.toml <upn> <computer$>
"""
import sys

sys.path.insert(0, "/opt/drs")

from drs import config as cfg  # noqa: E402
from drs.directory import Directory  # noqa: E402

c = cfg.load(sys.argv[1])
upn, computer = sys.argv[2], sys.argv[3]
d = Directory(c.ldap_uri, c.ldap_bind_dn, cfg.read_secret(c.ldap_password_file), c.ldap_base_dn,
              c.ldap_devices_dn, c.ldap_ca_file)
with d.session() as conn:
    user = d.user_by_upn(conn, upn)
    print("user      ", user)
    print("enrolment ", "member" if user and d.is_member(conn, user, c.ldap_enrol_group_dn) else "NOT a member")
    print("computer  ", d.computer(conn, computer))
    print("domain    ", d.domain_guid(conn))
    print("invocation", d.invocation_id(conn), "on", d.dc_hostname(conn))
