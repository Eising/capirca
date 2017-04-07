# Copyright 2017 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Clavister Firewall generator."""

import collections
import datetime
import logging

from lib import aclgenerator
from lib import nacaddr


class Error(Exception):
  """generic error class."""


class UnsupportedFilterError(Error):
  pass


class UnsupportedHeader(Error):
  pass


class ClavisterFWDuplicateTermError(Error):
  pass


class ClavisterFWVerbatimError(Error):
  pass


class ClavisterFWOptionError(Error):
  pass


class ClavisterFWDuplicateServiceError(Error):
  pass


class ClavisterFWTooLongName(Error):
  pass


class Term(aclgenerator.Term):
  """Representation of an individual term.

  This is mostly useful for the __str__() method.

  Args:
    obj: a policy.Term object
    term_type: type of filter to generate, e.g. inet or inet6
    filter_options: list of remaining target options (zones)
  """

  ACTIONS = {
      "accept": "Allow",
      "deny": "Deny",
  }

  def __init__(self, term, term_type, zones):
    self.term = term
    self.term_type = term_type
    self.folder = zones[1]
    self.extra_actions = []

  def __str__(self):
    """Render config output from this term object."""
    # Verify platform specific terms. Skip whole term if platform does not
    # match.
    # Nothing here for now

  def _Group(self, group):
    """If 1 item return it, else return [ item1 item2 ].

    Args:
      group: a list.  could be a list of strings (protocols) or a list of
             tuples (ports)

    Returns:
      rval: a string surrounded by '[' and '];' if len(group) > 1
            or with just ';' appended if len(group) == 1
    """

    def _FormattedGroup(el):
      """Return the actual formatting of an individual element.

      Args:
        el: either a string (protocol) or a tuple (ports)

      Returns:
        string: either the lower()'ed string or the ports, hyphenated
                if they're a range, or by itself if it's not.
      """
      if isinstance(el, str):
        return el.lower()
      elif isinstance(el, int):
        return str(el)
      # type is a tuple below here
      elif el[0] == el[1]:
        return "%d" % el[0]
      else:
        return "%d-%d" % (el[0], el[1])

    if len(group) > 1:
      rval = "[ " + " ".join([_FormattedGroup(x) for x in group]) + " ];"
    else:
      rval = _FormattedGroup(group[0]) + ";"
    return rval


class Service(object):

  service_map = {}

  TYPE_MAP = {
    "tcp": "ServiceTCPUDP",
    "udp": "ServiceTCPUDP",
    "icmpv6": "ServiceICMPv6",
    "icmp": "ServiceICMP"
  }

  ICMP_MAP = {
    "destination-unreachable": "DestinationUnreachable=Yes",
    "echo-reply": "EchoReply=Yes",
    "echo-request": "EchoRequest=Yes",
    "parameter-problem": "ParameterProblem=Yes",
    "redirect-message": "Redirect=Yes",
    "source-quench": "SourceQuenching=Yes",
    "time-exceeded": "TimeExceeded=Yes"
  }

  def __init__(self, ports, service_name,
               protocol):  # ports is a tuple of ports
    if (ports, protocol) in self.service_map:
      raise ClavisterFWDuplicateServiceError(
          ("You have a duplicate service. "
           "A service already exists on port(s): %s")
          % str(ports))

    final_service_name = "service-" + service_name + "-" + protocol


    for unused_k, v in Service.service_map.items():
      if v["name"] == final_service_name:
        raise ClavisterFWDuplicateServiceError(
            "You have a duplicate service. A service named %s already exists." %
            str(final_service_name))

    if len(final_service_name.decode("utf-8")) > 63:
      raise ClavisterFWTooLongName("Service name must be 63 characters max: %s" %
                                  str(final_service_name))
    if protocol in self.TYPE_MAP:
      self.service_map[(ports, protocol)] = {"name": final_service_name, "type": self.TYPE_MAP.get(protocol)}
    elif protocol.isdigit():
      self.service_map[(ports, protocol)] = {"name": final_service_name, "type": "ServiceIPProto" }


class Rule(object):
  """Extend the Term() class for Clavister Firewall Rules."""

  rules = {}

  def __init__(self, folder, terms):
    # Palo Alto Firewall rule keys
    self.options = {}
    self.options["folder"] = [folder]
    if not folder:
      raise ClavisterFWOptionError("Folder is empty.")
    self.ModifyOptions(terms)

  def ModifyOptions(self, terms):
    """Massage firewall rules into Palo Alto rules format."""
    term = terms.term
    self.options["source"] = []
    self.options["destination"] = []
    self.options["service"] = []
    self.options["action"] = "allow"

    # SOURCE-ADDRESS
    if term.source_address:
      saddr_check = set()
      for saddr in term.source_address:
        saddr_check.add(saddr.parent_token)
      saddr_check = sorted(saddr_check)
      for addr in saddr_check:
        self.options["source"].append(str(addr))
    else:
      self.options["source"].append("any")

    # DESTINATION-ADDRESS
    if term.destination_address:
      daddr_check = set()
      for daddr in term.destination_address:
        daddr_check.add(daddr.parent_token)
      daddr_check = sorted(daddr_check)
      for addr in daddr_check:
        self.options["destination"].append(str(addr))
    else:
      self.options["destination"].append("any")

    if term.action:
      self.options["action"] = term.action[0]

    if term.destination_port:
      ports = []
      for tup in term.destination_port:
        if len(tup) > 1 and tup[0] != tup[1]:
          ports.append(str(tup[0]) + "-" + str(tup[1]))
        else:
          ports.append(str(tup[0]))
      ports = tuple(ports)

      # check to see if this service already exists
      for p in term.protocol:
        if (ports, p) in Service.service_map:
          self.options["service"].append(Service.service_map[(ports, p)][
              "name"])
        else:
          # create service
          unused_new_service = Service(ports, term.name, p)
          self.options["service"].append(Service.service_map[(ports, p)][
              "name"])
    else:
      for p in term.protocol:
        if p == "icmp":
          ports = tuple(term.icmp_type)
          if (ports, p) in Service.service_map:
            self.options["service"].append(Service.service_map[(ports, p)][
              "name"])
          else:
            # create ICMP service
            unused_new_service = Service(ports, term.name, p)
            self.options["service"].append(Service.service_map[(ports, p)][
              "name"])
        elif p.isdigit():
          # This is raw ip proto
          ports = tuple([int(p)])
          if (ports, p) in Service.service_map:
            self.options["service"].append(Service.service_map[(ports, p)][
              "name"])
          else:
            # create IP service
            unused_new_service = Service(ports, term.name, p)
            self.options["service"].append(Service.service_map[(ports, p)][
              "name"])



      ports = () # ports should reflect the IPProto or ICMP codes

      # P


    rule_name = term.name
    if rule_name in self.rules:
      raise ClavisterFWDuplicateTermError(
          "You have a duplicate term. A term named %s already exists."
          % str(rule_name))

    self.rules[rule_name] = self.options


class ClavisterFW(aclgenerator.ACLGenerator):
  """ClavisterFW rendering class."""

  _PLATFORM = "clavister"
  SUFFIX = ".sgs"
  _SUPPORTED_AF = set(("inet", "inet6"))
  _AF_MAP = {"inet": (4,), "inet6": (6,)}
  _TERM_MAX_LENGTH = 31

  INDENT = "  "

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, supported_sub_tokens = super(ClavisterFW,
                                                   self)._BuildTokens()

    supported_tokens = {
        "action",
        "comment",
        "destination_address",
        "destination_port",
        "expiration",
        "icmp_type",
        "logging",
        "name",
        "protocol",
        "source_address",
        "source_port",
        "translated",
    }

    supported_sub_tokens.update({
        "action": {"accept", "deny"},
    })
    del supported_sub_tokens["option"]
    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    """Transform a policy object into a ClavisterFW object.

    Args:
      pol: policy.Policy object
      exp_info: print a info message when a term is set to expire
                in that many weeks

    Raises:
      UnsupportedFilterError: An unsupported filter was specified
      UnsupportedHeader: A header option exists that is not
      understood/usable
      ClavisterFWDuplicateTermError: Two terms were found with same name in
      same filter
    """
    self.clafw_policies = []
    self.addressbook = collections.OrderedDict()
    self.ports = []
    self.folder = ""
    self.policy_name = ""

    current_date = datetime.date.today()
    exp_info_date = current_date + datetime.timedelta(weeks=exp_info)
    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue

      filter_options = header.FilterOptions(self._PLATFORM)

      if (len(filter_options)) < 2 or filter_options[0] != "folder":
        raise UnsupportedFilterError(
            "Clavister Firewall filter arguments must specify folder"
        )

      self.folder = filter_options[1]

      if len(filter_options) > 2:
        filter_type = filter_options[2]
      else:
        filter_type = "inet"

      if filter_type not in self._SUPPORTED_AF:
        raise UnsupportedHeader(
            "Clavister Firewall Generator currently does not support"
            " %s as a header option" % (filter_type))

      term_dup_check = set()
      new_terms = []
      for term in terms:
        term.name = self.FixTermLength(term.name)
        if term.name in term_dup_check:
          raise ClavisterFWDuplicateTermError("You have a duplicate term: %s" %
                                             term.name)
        term_dup_check.add(term.name)

        if term.expiration:
          if term.expiration <= exp_info_date:
            logging.info("INFO: Term %s in policy %s>%s expires "
                         "in less than two weeks.", term.name, self.folder)
          if term.expiration <= current_date:
            logging.warn("WARNING: Term %s in policy %s>%s is expired and "
                         "will not be rendered.",
                         term.name, self.folder)
            continue

        for i in term.source_address_exclude:
          term.source_address = nacaddr.RemoveAddressFromList(
              term.source_address, i)
        for i in term.destination_address_exclude:
          term.destination_address = nacaddr.RemoveAddressFromList(
              term.destination_address, i)

        for addr in term.source_address:
          self._BuildAddressBook(addr)
        for addr in term.destination_address:
          self._BuildAddressBook(addr)

        new_term = Term(term, filter_type, filter_options)
        new_terms.append(new_term)
        tmp_icmptype = new_term.NormalizeIcmpTypes(term.icmp_type,
                                                   term.protocol, filter_type)
        # NormalizeIcmpTypes returns [''] for empty, convert to [] for
        # eval
        normalized_icmptype = tmp_icmptype if tmp_icmptype != [""] else []
        protocol = term.protocol

      self.clafw_policies.append((header, new_terms, filter_options))
      # create Rule object
      for term in new_terms:
        unused_rule = Rule(self.folder, term)

  def _BuildAddressBook(self, address):
    """Create the address book configuration entries.

    Args:
      zone: the zone these objects will reside in
      address: a naming library address object
    """
    if not self.addressbook:
      self.addressbook = collections.OrderedDict()

    if type(address) is nacaddr.IPv4:
      af = "IP4"
    else:
      af = "IP6"

    parent_name = str(address.parent_token + "_" + af)

    if parent_name not in self.addressbook:
      self.addressbook[parent_name] = []

    for ip in self.addressbook[parent_name]:
      if str(address) == str(ip[0]):
        return
    counter = len(self.addressbook[parent_name])
    name = "%s_%s" % (parent_name, str(counter))
    self.addressbook[parent_name].append((address, name))

  def _SortAddressBookNumCheck(self, item):
    """Used to give a natural order to the list of acl entries.

    Args:
      item: string of the address book entry name

    Returns:
      returns the characters and number
    """

    item_list = item.split("_")
    num = item_list.pop(-1)
    if isinstance(item_list[-1], int):
      set_number = item_list.pop(-1)
      num = int(set_number) * 1000 + int(num)
    alpha = "_".join(item_list)
    if num:
      return (alpha, int(num))
    return (alpha, 0)

  def _BuildPort(self, ports):
    """Transform specified ports into list and ranges.

    Args:
      ports: a policy terms list of ports

    Returns:
      port_list: list of ports and port ranges
    """
    port_list = []
    for i in ports:
      if i[0] == i[1]:
        port_list.append(str(i[0]))
      else:
        port_list.append("%s-%s" % (str(i[0]), str(i[1])))
    return port_list

  def __str__(self):
    """Render the output of the ClavisterFirewall policy into config."""

    # ADDRESS
    address_entries = []

    address_book_names_dict = {}
    address_book_groups_dict = {}

    # building individual addresses dictionary
    groups = sorted(self.addressbook)
    for group in groups:
      for address, name in self.addressbook[group]:
        if name in address_book_names_dict:
          if address_book_names_dict[name].Contains(address):
            continue
        address_book_names_dict[name] = address

      # building individual address-group dictionary
      for group in groups:
        group_names = []
        for address, name in self.addressbook[group]:
          group_names.append(name)
        address_book_groups_dict[group] = group_names

    # sort address books and address sets
    address_book_groups_dict = collections.OrderedDict(
        sorted(address_book_groups_dict.items()))
    address_book_keys = sorted(
        address_book_names_dict.keys(), key=self._SortAddressBookNumCheck)

    for name in address_book_keys:
      if type(address_book_names_dict[name]) is nacaddr.IPv4:
        address_entries.append("add IP4Address " + name +
                               " Address=" + str(address_book_names_dict[name]))
      elif type(address_book_names_dict[name]) is nacaddr.IPv6:
        address_entries.append("add IP6Address " + name +
                               " Address=" + str(address_book_names_dict[name]))

      address_group_entries = []

    for group, address_list in address_book_groups_dict.items():
      if type(address_book_names_dict[address_list[0]]) is nacaddr.IPv4:
        address_group_entries.append("add IP4Group " + group +
                                     " Members=" + ",".join(address_list))
      elif type(address_book_names_dict[address_list[0]]) is nacaddr.IPv6:
        address_group_entries.append("add IP6Group " + group +
                                     " Members=" + ",".join(address_list))


    # SERVICES
    service = []

    for k, v in Service.service_map.items():
      tup = str(k[0])[1:-1]
      if tup and tup[-1] == ",":
        tup = tup[:-1]
      if k[1] == "tcp" or k[1] == "udp":
        service.append("add " + v["type"] + " " + v["name"] +
                       " DestinationPorts=" + tup.replace("'", "") +
                       " Type=" + k[1].upper()
        )
      elif k[1].isdigit():
        service.append("add " + v["type"] + " " + v["name"] +
                       " IPProto=" + k[1])
      elif k[1] == "icmp":
        icmp_options = []
        if len(k[0]) > 0:
          for icmp_type in k[0]:
            if icmp_type in Service.ICMP_MAP:
              icmp_options.append(Service.ICMP_MAP.get(str(icmp_type)))
          service.append("add " + v["type"] + " " + v["name"] +
                        " MessageTypes=Specific " + " ".join(icmp_options))
        else:
          service.append("add " + v["type"] + " " + v["name"] +
                         " MessageTypes=All")


    # RULES
    rules = []
    rules.append("delete IPRuleFolder " + self.folder + " -force")
    rules.append("add IPRuleFolder " + self.folder)
    rules.append("cc IPRuleFolder " + self.folder)


    for name, options in Rule.rules.items():
      if options["source"]:
        source = options["source"][0]
      else:
        source = "all-nets"

      if options["destination"]:
        destination = options["destination"][0]
      else:
        destination = "all-nets"


      keys = address_book_groups_dict.keys()
      rule4 = False
      rule6 = False

      for k in keys:
        if k.startswith(destination) and k.endswith('IP4'):
          rule4 = True
        if k.startswith(destination) and k.endswith('IP6'):
          rule6 = True

      sourcev4 = source + "_IP4"
      destinationv4 = destination + "_IP4"
      sourcev6 = source + "_IP6"
      destinationv6 = destination + "_IP6"
      if rule4 and (sourcev4 in keys and destinationv4 in keys):
        source = sourcev4
        destination = destinationv4
        if not (source in keys and destination in keys):
          # Source and destinations aren't same address family
          continue
        if len(options["service"]) == 1:
          action = Term.ACTIONS.get(str(options["action"]))
          rules.append(self.INDENT + "add IPPolicy Name=" + name + # ensure 31 max for name
                      " SourceInterface=any DestinationInterface=any " +
                      "SourceNetwork=" + source + " DestinationNetwork=" +
                      destination + " Service=" + options["service"][0] +
                      " Action=" + action)

        elif not options["service"]:
          rules.append(self.INDENT + "add IPPolicy Name=" + name + # ensure 31 max for name
                      " SourceInterface=any DestinationInterface=any " +
                      "SourceNetwork=" + source + " DestinationNetwork=" +
                      destination + " Service=all-services" +
                      " Action=" + action)
        elif len(options["service"]) > 1:
          for s in enumerate(options["services"]):
            rules.append(self.INDENT + "add IPPolicy Name=" + name + "_" + s[0] +# ensure 31 max for name
                        " SourceInterface=any DestinationInterface=any " +
                        "SourceNetwork=" + source + " DestinationNetwork=" +
                        destination + " Service=" +
                        " Action=" + action)

      if rule6 and (sourcev6 in keys and destinationv6 in keys):
        source = sourcev6
        destination = destinationv6
        if len(options["service"]) == 1:
          action = Term.ACTIONS.get(str(options["action"]))
          rules.append(self.INDENT + "add IPPolicy Name=" + name + # ensure 31 max for name
                      " SourceInterface=any DestinationInterface=any " +
                      "SourceNetwork=" + source + " DestinationNetwork=" +
                      destination + " Service=" + options["service"][0] +
                      " Action=" + action)

        elif not options["service"]:
          rules.append(self.INDENT + "add IPPolicy Name=" + name + # ensure 31 max for name
                      " SourceInterface=any DestinationInterface=any " +
                      "SourceNetwork=" + source + " DestinationNetwork=" +
                      destination + " Service=all-services" +
                      " Action=" + action)
        elif len(options["service"]) > 1:
          for s in enumerate(options["services"]):
            rules.append(self.INDENT + "add IPPolicy Name=" + name + "_" + s[0] +# ensure 31 max for name
                        " SourceInterface=any DestinationInterface=any " +
                        "SourceNetwork=" + source + " DestinationNetwork=" +
                        destination + " Service=" +
                        " Action=" + action)


    return ("\n".join(address_entries) + "\n\n" + "\n".join(address_group_entries) +
            "\n\n" + "\n".join(service) + "\n\n" + "\n".join(rules))
