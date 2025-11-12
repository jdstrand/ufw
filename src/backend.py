"""backend.py: interface for ufw backends"""

#
# Copyright 2008-2024 Canonical Ltd.
# Copyright 2025 Jamie Strandboge
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import abc
import errno
import gettext
import os
import pwd
import re
import stat
import sys
from typing import Optional, List, Dict, Tuple

import ufw.util
from ufw.util import error, warn, debug, _findpath
from ufw.common import UFWError, UFWRule
import ufw.applications
import ufw.common

# Internationalization
tr = gettext.gettext


class UFWBackend(metaclass=abc.ABCMeta):
    """Interface for backends"""

    def __init__(
        self,
        name: str,
        dryrun: bool,
        extra_files: Optional[Dict[str, str]] = None,
        rootdir: Optional[str] = None,
        datadir: Optional[str] = None,
    ) -> None:
        self.defaults: Dict[str, str] = {}
        self.name = name
        self.dryrun = dryrun
        self.rootdir = rootdir if rootdir is not None else None
        self.datadir = datadir if rootdir is not None else None
        self.rules = []
        self.rules6 = []

        p = _findpath(ufw.common.config_dir, datadir)
        self.files = {
            "defaults": os.path.join(p, "default/ufw"),
            "conf": os.path.join(p, "ufw/ufw.conf"),
            "apps": os.path.join(p, "ufw/applications.d"),
        }
        if extra_files is not None:
            self.files.update(extra_files)

        self.loglevels = {"off": 0, "low": 100, "medium": 200, "high": 300, "full": 400}

        self.do_checks = ufw.common.do_checks
        self._do_checks()
        self._get_defaults()
        self._read_rules()  # Abstract method implemented in subclasses

        self.profiles = ufw.applications.get_profiles(self.files["apps"])

        self.iptables = os.path.join(ufw.common.iptables_dir, "iptables")
        self.iptables_restore = os.path.join(
            ufw.common.iptables_dir, "iptables-restore"
        )
        self.ip6tables = os.path.join(ufw.common.iptables_dir, "ip6tables")
        self.ip6tables_restore = os.path.join(
            ufw.common.iptables_dir, "ip6tables-restore"
        )

        try:
            self.iptables_version = ufw.util.get_iptables_version(self.iptables)
        except OSError:  # pragma: no coverage
            err_msg = tr("Couldn't determine iptables version")
            raise UFWError(err_msg)

        # Initialize via initcaps only when we need it (LP: #1044361)
        self.caps = None

    def initcaps(self) -> None:
        """Initialize the capabilities database. This needs to be called
        before accessing the database."""

        # Only initialize if not initialized already
        if self.caps is not None:
            return

        self.caps = {}
        self.caps["limit"] = {}

        # Set defaults for dryrun, non-root, etc
        self.caps["limit"]["4"] = True
        self.caps["limit"]["6"] = False  # historical default for the testsuite

        # Try to get capabilities from the running system if root
        if (
            self.do_checks and os.getuid() == 0 and not self.dryrun
        ):  # pragma: no coverage
            # v4
            try:
                nf_caps = ufw.util.get_netfilter_capabilities(self.iptables)
            except OSError as e:
                msg = "initcaps\n%s" % e
                if self.is_enabled():
                    error(msg)
                warn(msg)
                return

            if "recent-set" in nf_caps and "recent-update" in nf_caps:
                self.caps["limit"]["4"] = True
            else:
                self.caps["limit"]["4"] = False

            # v6 (skip capabilities check for ipv6 if ipv6 is disabled in ufw
            # because the system may not have ipv6 support (LP: #1039729)
            if self.use_ipv6():
                try:
                    nf_caps = ufw.util.get_netfilter_capabilities(self.ip6tables)
                except OSError as e:
                    error("initcaps\n%s" % e)
                if "recent-set" in nf_caps and "recent-update" in nf_caps:
                    self.caps["limit"]["6"] = True
                else:
                    self.caps["limit"]["6"] = False

    def is_enabled(self) -> bool:
        """Is firewall configured as enabled"""
        if "enabled" in self.defaults and self.defaults["enabled"] == "yes":
            return True
        return False

    def use_ipv6(self) -> bool:
        """Is firewall configured to use IPv6"""
        if (
            "ipv6" in self.defaults
            and self.defaults["ipv6"] == "yes"
            and os.path.exists("/proc/sys/net/ipv6")
        ):
            return True
        return False

    def _get_default_policy(
        self, primary: str = "input", check_forward: bool = False
    ) -> str:
        """Get default policy for specified primary chain"""
        policy = "default_" + primary + "_policy"

        rstr = ""
        if self.defaults[policy] == "accept":
            rstr = "allow"
        elif self.defaults[policy] == "reject":
            rstr = "reject"
        else:
            rstr = "deny"

        if check_forward and primary == "forward":
            enabled = False
            err_msg = tr("problem running sysctl")

            (rc, out) = ufw.util.cmd(["sysctl", "net.ipv4.ip_forward"])
            if rc != 0:  # pragma: no cover
                raise UFWError(err_msg)
            if "1" in str(out):
                enabled = True

            # IPv6 may be disabled, so ignore sysctl output
            if self.use_ipv6():
                (rc, out) = ufw.util.cmd(["sysctl", "net.ipv6.conf.default.forwarding"])
                if rc == 0 and "1" in str(out):
                    enabled = True

                (rc, out) = ufw.util.cmd(["sysctl", "net.ipv6.conf.all.forwarding"])
                if rc == 0 and "1" in str(out):
                    enabled = True

            if not enabled:
                rstr = "disabled"

        return rstr

    # Don't do coverage on this cause we don't run the unit tests as root
    def _do_checks(self) -> bool:  # pragma: no coverage
        """Perform basic security checks:
        is setuid or setgid (for non-Linux systems)
        checks that script is owned by root
        checks that every component in absolute path are owned by root
        warn if script is group writable
        warn if part of script path is group writable

        Doing this at the beginning causes a race condition with later
        operations that don't do these checks.  However, if the user running
        this script is root, then need to be root to exploit the race
        condition (and you are hosed anyway...)
        """

        if not self.do_checks:
            err_msg = tr("Checks disabled")
            warn(err_msg)
            return True

        # Not needed on Linux, but who knows the places we will go...
        if os.getuid() != os.geteuid():
            err_msg = tr("ERROR: this script should not be SUID")
            raise UFWError(err_msg)
        if os.getgid() != os.getegid():
            err_msg = tr("ERROR: this script should not be SGID")
            raise UFWError(err_msg)

        uid = os.getuid()
        if uid != 0:
            err_msg = tr("You need to be root to run this script")
            raise UFWError(err_msg)

        # Use these so we only warn once
        warned_world_write = {}
        warned_group_write = {}
        warned_owner = {}

        profiles = []
        if not os.path.isdir(self.files["apps"]):
            warn_msg = tr("'%s' does not exist") % (self.files["apps"])
            warn(warn_msg)
        else:
            pat = re.compile(r"^\.")
            for profile in os.listdir(self.files["apps"]):
                if not pat.search(profile):
                    profiles.append(os.path.join(self.files["apps"], profile))

        for path in (
            list(self.files.values()) + [os.path.abspath(sys.argv[0])] + profiles
        ):
            if not path.startswith("/"):
                path = "%s/%s" % (os.getcwd(), path)
            while True:
                debug("Checking " + path)
                if path == self.files["apps"] and not os.path.isdir(self.files["apps"]):
                    break

                try:
                    statinfo = os.stat(path)
                    mode = statinfo[stat.ST_MODE]
                except OSError:
                    err_msg = tr("Couldn't stat '%s'") % (path)
                    raise UFWError(err_msg)
                except Exception:
                    raise

                # snaps and clicks unpack to this, so handle it
                click_user = "clickpkg"
                snap_user = "snappypkg"
                is_unpack_user = False
                try:
                    if (
                        pwd.getpwuid(statinfo.st_uid)[0] == click_user
                        or pwd.getpwuid(statinfo.st_uid)[0] == snap_user
                    ):
                        is_unpack_user = True
                except KeyError:
                    pass

                if (
                    statinfo.st_uid != 0
                    and not is_unpack_user
                    and path not in warned_owner
                ):
                    warn_msg = tr(
                        "uid is %(uid)s but '%(path)s' is owned by " "%(st_uid)s"
                    ) % (
                        {"uid": str(uid), "path": path, "st_uid": str(statinfo.st_uid)}
                    )
                    warn(warn_msg)
                    warned_owner[path] = True
                if mode & stat.S_IWOTH and path not in warned_world_write:
                    warn_msg = tr("%s is world writable!") % (path)
                    warn(warn_msg)
                    warned_world_write[path] = True
                if (
                    mode & stat.S_IWGRP
                    and path not in warned_group_write
                    and statinfo.st_gid != 0
                ):
                    warn_msg = tr("%s is group writable!") % (path)
                    warn(warn_msg)
                    warned_group_write[path] = True

                if path == "/":
                    break

                last_path = path
                path = os.path.dirname(path)
                if not path:
                    raise OSError(
                        errno.ENOENT, "Could not find parent for '%s'" % (last_path)
                    )

        for f in self.files:
            if f != "apps" and not os.path.isfile(self.files[f]):
                err_msg = tr("'%(f)s' file '%(name)s' does not exist") % (
                    {"f": f, "name": self.files[f]}
                )
                raise UFWError(err_msg)

        return True

    def _get_defaults(self) -> None:
        """Get all settings from defaults file"""
        self.defaults = {}
        for f in [self.files["defaults"], self.files["conf"]]:
            try:
                orig = ufw.util.open_file_read(f)
            except Exception:  # pragma: no coverage
                err_msg = tr("Couldn't open '%s' for reading") % (f)
                raise UFWError(err_msg)
            pat = re.compile(r'^\w+="?\w+"?')
            for line in orig:
                if pat.search(line):
                    tmp = re.split(r"=", line.strip())
                    self.defaults[tmp[0].lower()] = tmp[1].lower().strip("\"'")

            orig.close()

        # do some quick default policy checking
        policies = ["accept", "drop", "reject"]
        for c in ["input", "output", "forward"]:
            if "default_%s_policy" % (c) not in self.defaults:
                err_msg = tr("Missing policy for '%s'" % (c))
                raise UFWError(err_msg)
            p = self.defaults["default_%s_policy" % (c)]
            if p not in policies:
                err_msg = tr(
                    "Invalid policy '%(policy)s' for '%(chain)s'"
                    % ({"policy": p, "chain": c})
                )
                raise UFWError(err_msg)

    def set_default(self, fn: str, opt: str, value: str) -> None:
        """Sets option in defaults file"""
        if not re.match(r"^[\w_]+$", opt):
            err_msg = tr("Invalid option")
            raise UFWError(err_msg)

        # Perform this here so we can present a nice error to the user rather
        # than a traceback
        if not os.access(fn, os.W_OK):
            err_msg = tr("'%s' is not writable" % (fn))
            raise UFWError(err_msg)

        fns = ufw.util.open_files(fn)
        fd = fns["tmp"]

        found = False
        pat = re.compile(r"^" + opt + "=")
        for line in fns["orig"]:
            if pat.search(line):
                ufw.util.write_to_file(fd, opt + "=" + value + "\n")
                found = True
            else:
                ufw.util.write_to_file(fd, line)

        # Add the entry if not found
        if not found:
            ufw.util.write_to_file(fd, opt + "=" + value + "\n")

        try:
            ufw.util.close_files(fns)
        except Exception:  # pragma: no coverage
            raise

        # Now that the files are written out, update value in memory
        self.defaults[opt.lower()] = value.lower().strip("\"'")

    def set_default_application_policy(self, policy: str) -> str:
        """Sets default application policy of firewall"""
        if not self.dryrun:
            if policy == "allow":
                self.set_default(
                    self.files["defaults"], "DEFAULT_APPLICATION_POLICY", '"ACCEPT"'
                )
            elif policy == "deny":
                self.set_default(
                    self.files["defaults"], "DEFAULT_APPLICATION_POLICY", '"DROP"'
                )
            elif policy == "reject":
                self.set_default(
                    self.files["defaults"], "DEFAULT_APPLICATION_POLICY", '"REJECT"'
                )
            elif policy == "skip":
                self.set_default(
                    self.files["defaults"], "DEFAULT_APPLICATION_POLICY", '"SKIP"'
                )
            else:
                err_msg = tr("Unsupported policy '%s'") % (policy)
                raise UFWError(err_msg)

        rstr = tr("Default application policy changed to '%s'") % (policy)

        return rstr

    def get_app_rules_from_template(self, template: UFWRule) -> List[UFWRule]:
        """Return a list of UFWRules based on the template rule"""
        rules = []
        profile_names = list(self.profiles.keys())

        if template.dport in profile_names and template.sport in profile_names:
            dports = ufw.applications.get_ports(self.profiles[template.dport])
            sports = ufw.applications.get_ports(self.profiles[template.sport])
            for i in dports:
                tmp = template.dup_rule()
                tmp.dapp = ""
                tmp.set_port("any", "src")
                (port, proto) = ufw.util.parse_port_proto(i)
                tmp.set_protocol(proto)
                tmp.set_port(port, "dst")

                tmp.dapp = template.dapp

                if template.dport == template.sport:
                    # Just use the same ports as dst for src when they are the
                    # same to avoid duplicate rules
                    tmp.sapp = ""
                    (port, proto) = ufw.util.parse_port_proto(i)
                    tmp.set_protocol(proto)
                    tmp.set_port(port, "src")

                    tmp.sapp = template.sapp
                    rules.append(tmp)
                else:
                    for j in sports:
                        rule = tmp.dup_rule()
                        rule.sapp = ""
                        (port, proto) = ufw.util.parse_port_proto(j)
                        rule.set_protocol(proto)
                        rule.set_port(port, "src")

                        if rule.protocol == "any":
                            rule.set_protocol(tmp.protocol)

                        rule.sapp = template.sapp
                        rules.append(rule)
        elif template.sport in profile_names:
            for p in ufw.applications.get_ports(self.profiles[template.sport]):
                rule = template.dup_rule()
                rule.sapp = ""
                (port, proto) = ufw.util.parse_port_proto(p)
                rule.set_protocol(proto)
                rule.set_port(port, "src")

                rule.sapp = template.sapp
                rules.append(rule)
        elif template.dport in profile_names:
            for p in ufw.applications.get_ports(self.profiles[template.dport]):
                rule = template.dup_rule()
                rule.dapp = ""
                (port, proto) = ufw.util.parse_port_proto(p)
                rule.set_protocol(proto)
                rule.set_port(port, "dst")

                rule.dapp = template.dapp
                rules.append(rule)

        if len(rules) < 1:
            err_msg = tr("No rules found for application profile")
            raise UFWError(err_msg)

        return rules

    def update_app_rule(self, profile: str) -> Tuple[str, bool]:
        """Update rule for profile in place. Returns result string and bool
        on whether or not the profile is used in the current ruleset.
        """
        updated_rules = []
        updated_rules6 = []
        last_tuple = ""
        rstr = ""
        updated_profile = False

        # Remember, self.rules is from user[6].rules, and not the running
        # firewall.
        for r in self.rules + self.rules6:
            if r.dapp == profile or r.sapp == profile:
                # We assume that the rules are in app rule order. Specifically,
                # if app rule has multiple rules, they are one after the other.
                # If the rule ordering changes, the below will have to change.
                tupl = r.get_app_tuple()
                if tupl == last_tuple:
                    # Skip the rule if seen this tuple already (ie, it is part
                    # of a known tuple).
                    continue
                else:
                    # Have a new tuple, so find and insert new app rules here
                    template = r.dup_rule()
                    template.set_protocol("any")
                    if template.dapp != "":
                        template.set_port(template.dapp, "dst")
                    if template.sapp != "":
                        template.set_port(template.sapp, "src")
                    new_app_rules = self.get_app_rules_from_template(template)

                    for new_r in new_app_rules:
                        new_r.normalize()
                        if new_r.v6:
                            updated_rules6.append(new_r)
                        else:
                            updated_rules.append(new_r)

                    last_tuple = tupl
                    updated_profile = True
            else:
                if r.v6:
                    updated_rules6.append(r)
                else:
                    updated_rules.append(r)

        if updated_profile:
            self.rules = updated_rules
            self.rules6 = updated_rules6
            rstr += tr("Rules updated for profile '%s'") % (profile)

            try:
                self._write_rules(False)  # ipv4
                self._write_rules(True)  # ipv6
            except Exception:  # pragma: no coverage
                err_msg = tr("Couldn't update application rules")
                raise UFWError(err_msg)

        return (rstr, updated_profile)

    def find_application_name(self, profile_name: str) -> str:
        """Find the application profile name for profile_name"""
        if profile_name in self.profiles:
            return profile_name

        match = ""
        matches = 0
        for n in list(self.profiles.keys()):
            if n.lower() == profile_name.lower():
                match = n
                matches += 1

        debug_msg = "'%d' matches for '%s'" % (matches, profile_name)
        debug(debug_msg)
        if matches == 1:
            return match
        elif matches > 1:
            err_msg = tr(
                "Found multiple matches for '%s'. Please use exact profile name"
            ) % (profile_name)
        else:
            err_msg = tr("Could not find a profile matching '%s'") % (profile_name)
        raise UFWError(err_msg)

    def find_other_position(self, position: int, v6: bool) -> int:
        """Return the absolute position in the other list of the rule with the
        user position of the given list. For example, find_other_position(4,
        True) will return the absolute position of the rule in the ipv4 list
        matching the user specified '4' rule in the ipv6 list.
        """
        # Invalid search (v6 rule with too low position)
        if v6 and position > len(self.rules6):
            raise ValueError()

        # Invalid search (v4 rule with too high position)
        if not v6 and position > len(self.rules):
            raise ValueError()

        if position < 1:
            raise ValueError()

        rules = []
        if v6:
            rules = self.rules6
        else:
            rules = self.rules

        # self.rules[6] is a list of tuples. Some application rules have
        # multiple tuples but the user specifies by ufw rule, not application
        # tuple, so we need to find how many tuples there are leading up to
        # the specified position, which we can then use as an offset for
        # getting the proper match_rule.
        app_rules = {}
        tuple_offset = 0
        for i, r in enumerate(rules):
            if i >= position:
                break
            tupl = ""
            if r.dapp != "" or r.sapp != "":
                tupl = r.get_app_tuple()

                if tupl in app_rules:
                    tuple_offset += 1
                else:
                    app_rules[tupl] = True

        rules = []
        if v6:
            rules = self.rules
            match_rule = self.rules6[position - 1 + tuple_offset].dup_rule()
            match_rule.set_v6(False)
        else:
            rules = self.rules6
            match_rule = self.rules[position - 1 + tuple_offset].dup_rule()
            match_rule.set_v6(True)

        count = 1
        for r in rules:
            if UFWRule.match(r, match_rule) == 0:
                return count
            count += 1

        return 0

    def get_loglevel(self) -> Tuple[int, str]:
        """Gets current log level of firewall"""
        level = 0
        rstr = tr("Logging: ")
        if "loglevel" not in self.defaults or self.defaults["loglevel"] not in list(
            self.loglevels.keys()
        ):
            level = -1
            rstr += tr("unknown")
        else:
            level = self.loglevels[self.defaults["loglevel"]]
            if level == 0:
                rstr += "off"
            else:
                rstr += "on (%s)" % (self.defaults["loglevel"])
        return (level, rstr)

    def set_loglevel(self, level: str) -> str:
        """Sets log level of firewall"""
        if level not in list(self.loglevels.keys()) + ["on"]:
            err_msg = tr("Invalid log level '%s'") % (level)
            raise UFWError(err_msg)

        new_level = level
        if level == "on":
            if "loglevel" not in self.defaults or self.defaults["loglevel"] == "off":
                new_level = "low"
            else:
                new_level = self.defaults["loglevel"]

        self.set_default(self.files["conf"], "LOGLEVEL", new_level)
        self.update_logging(new_level)

        if new_level == "off":
            return tr("Logging disabled")
        else:
            return tr("Logging enabled")

    def get_rules(self) -> List[UFWRule]:
        """Return list of all rules"""
        return self.get_rules_ipv4() + self.get_rules_ipv6()

    def get_rules_ipv4(self) -> List[UFWRule]:
        """Return list of IPv4 rules"""
        return self.rules

    def get_rules_ipv6(self) -> List[UFWRule]:
        """Return list of IPv6 rules"""
        return self.rules6

    def get_rules_count(self, v6: bool) -> int:
        """Return number of ufw rules (not iptables rules)"""
        rules = []
        if v6:
            rules = self.rules6
        else:
            rules = self.rules

        count = 0
        app_rules = {}
        for r in rules:
            tupl = ""
            if r.dapp != "" or r.sapp != "":
                tupl = r.get_app_tuple()

                if tupl in app_rules:
                    debug("Skipping found tuple '%s'" % (tupl))
                    continue
                else:
                    app_rules[tupl] = True
            count += 1

        return count

    def get_rule_by_number(self, num: int) -> Optional[UFWRule]:
        '''Return rule specified by number seen via "status numbered"'''
        rules = self.get_rules()

        count = 1
        app_rules = {}
        for r in rules:
            tupl = ""
            if r.dapp != "" or r.sapp != "":
                tupl = r.get_app_tuple()

                if tupl in app_rules:
                    debug("Skipping found tuple '%s'" % (tupl))
                    continue
                else:
                    app_rules[tupl] = True
            if count == int(num):
                return r
            count += 1

        return None

    def get_matching(self, rule: UFWRule) -> List[int]:
        """See if there is a matching rule in the existing ruleset. Note this
        does not group rules by tuples."""
        matched = []
        count = 0
        for r in self.get_rules():
            count += 1
            ret = ufw.common.UFWRule.fuzzy_dst_match(rule, r)
            if ret < 1:
                matched.append(count)

        return matched

    # API overrides
    @abc.abstractmethod
    def set_default_policy(self, policy: str, direction: str) -> str:
        """Set default policy for specified direction"""
        raise NotImplementedError  # pragma: nocover

    @abc.abstractmethod
    def get_running_raw(self, rules_type: str) -> str:
        """Get status of running firewall"""
        raise NotImplementedError  # pragma: nocover

    @abc.abstractmethod
    def get_status(self, verbose: bool, show_count: bool) -> str:
        """Get managed rules"""
        raise NotImplementedError  # pragma: nocover

    @abc.abstractmethod
    def set_rule(self, rule: UFWRule, allow_reload: bool) -> str:
        """Update firewall with rule"""
        raise NotImplementedError  # pragma: nocover

    @abc.abstractmethod
    def start_firewall(self) -> None:
        """Start the firewall"""
        raise NotImplementedError  # pragma: nocover

    @abc.abstractmethod
    def stop_firewall(self) -> None:
        """Stop the firewall"""
        raise NotImplementedError  # pragma: nocover

    @abc.abstractmethod
    def get_app_rules_from_system(self, template: UFWRule, v6: bool) -> List[UFWRule]:
        """Get a list if rules based on template"""
        raise NotImplementedError  # pragma: nocover

    @abc.abstractmethod
    def update_logging(self, level: str) -> None:
        """Update loglevel of running firewall"""
        pass
        raise NotImplementedError  # pragma: nocover

    @abc.abstractmethod
    def reset(self) -> str:
        """Reset the firewall"""
        raise NotImplementedError  # pragma: nocover

    @abc.abstractmethod
    def _read_rules(self) -> None:
        """Read rules from the system"""
        raise NotImplementedError  # pragma: nocover

    @abc.abstractmethod
    def _write_rules(self, v6: bool = False) -> None:
        """Write rules to the system"""
        raise NotImplementedError  # pragma: nocover
