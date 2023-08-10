#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
from datetime import datetime
import time

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.protocols.gmpv224 import AliveTest, HostsOrdering
from gvm.transforms import EtreeCheckCommandTransform

import helper
from helper import log_debug,log_info,log_warning,log_error,set_progress

class OVasConfig:
    def __init__(self):
        self.ovas_sock = None
        self.ovas_uname= None
        self.ovas_pass = None
        self.ovas_maxhosts = None
        self.ovas_maxchecks= None


def main(params):
    src_host_ip=None
    scan_range= None
    scan_port = None
    scan_protocol = None
    
    conf = OVasConfig()
    conf.ovas_sock = params["ovas_sock" ]
    conf.ovas_uname= params["ovas_uname"]
    conf.ovas_pass = params["ovas_pass" ]
    conf.ovas_maxhosts = params["ovas_maxhosts"]
    conf.ovas_maxchecks= params["ovas_maxchecks"]
    
    scan_range = params["scan_range"]
    scan_port  = params["scan_port"]
    scan_protocol = params["scan_protocol"]
    
    return vulnerability_scan(conf, scan_range, scan_port, scan_protocol)

def ip2int(ipaddr: str) -> int:
    """(INTERNAL) contert to String address to 32-bit integer.

    Parameters
    ----------
    ipaddr : str

    Returns
    -------
    int
    """
    rval = 0
    for ip_part in ipaddr.split("."):
        rval = rval * 256 + int(ip_part)
    return rval

def get_timestamp(format="%Y%m%d%H%M%S"):
    """(INTERNAL) Return present time as string.

    Parameters
    ----------
    format : str, optional
        format of time, by default "%Y%m%d%H%M%S"

    Returns
    -------
    str
        string of present time
    """
    now = datetime.now()
    return now.strftime(format)
        
def vulnerability_scan(
    conf:OVasConfig,
    scan_range: str | list,
    scan_port: str = "1-1024",
    scan_protocol: str = "TCP",
):
    
    ts = get_timestamp()

    # use openvas python gvm
    conn = UnixSocketConnection(path=conf.ovas_sock)
    with Gmp(connection=conn, transform=EtreeCheckCommandTransform()) as gmp:
        gmp.authenticate(conf.ovas_uname, conf.ovas_pass)

        #
        # create scan target
        #

        ## hosts
        if isinstance(scan_range, str):
            target_hosts_in = [scan_range]
        else:
            target_hosts_in = scan_range

        target_hosts = list()

        ### this method allows network address which netmask is represented using dot-notation (such as "192.168.0.0/255.255.255.0") as a target,
        ### but openvas can only accepts network address in CIDR form(address + prefix length). So, it is neccesary to convert such notation into
        ### CIDR form ( 192.168.0.0/24, for example )
        for target in target_hosts_in:
            if "/" in target:
                addr, mask = target.split("/", 1)
                if "." in mask:
                    ip32 = ip2int(mask)
                    if ip32 == 0 or ip32 > 0xFFFFFFFF:
                        raise RuntimeError("invalid netmask")
                    bit = 1
                    for prefix_len in range(32, 0, -1):
                        if ip32 & bit != 0:
                            break
                        bit <<= 1
                    target = f"{addr}/{prefix_len}"

            target_hosts.append(target)

        ## ports
        if scan_protocol.upper() == "TCP":
            prefix = "T"
        elif scan_protocol.upper() == "UDP":
            prefix = "U"
        else:
            raise RuntimeError("invalid protocol")

        port_range = f"{prefix}:{scan_port}"

        target_name = f"TARGET_{ts}"
        target = gmp.create_target(
            target_name,
            hosts=target_hosts,
            port_range=port_range,
            alive_test=AliveTest.ICMP_AND_TCP_ACK_SERVICE_PING,
        )
        target_id = target.attrib["id"]

        #
        # select scanner
        #
        scanner_name = "OpenVAS Default"
        scanners = gmp.get_scanners()
        scanner = scanners.xpath(f'./scanner/name[text()="{scanner_name}"]/..')

        scanner_id = scanner[0].attrib["id"]

        #
        # select scan config
        #
        config_name = "Full and fast"
        configs = gmp.get_scan_configs()
        config = configs.xpath(f'./config/name[text()="{config_name}"]/..')
        config_id = config[0].attrib["id"]

        #
        # create task
        #
        ovas_task_name = f"TASK_{ts}"
        ovas_task = gmp.create_task(
            ovas_task_name,
            target_id=target_id,
            scanner_id=scanner_id,
            config_id=config_id,
            hosts_ordering=HostsOrdering.RANDOM,
            preferences={
                "max_hosts": conf.ovas_maxhosts,
                "max_checks": conf.ovas_maxchecks,
            },
        )
        task_id = ovas_task.attrib["id"]

        #
        # start task
        #
        gmp.start_task(task_id)

        #
        # wait until scan is finished
        #
        while True:
            ovas_task = gmp.get_task(task_id)
            progress = int(ovas_task.xpath("./task/progress/text()")[0])
            if progress >= 0:
                set_progress(progress)
            else:
                break
            time.sleep(5)

        #
        # get result
        #
        results = gmp.get_results(
            details=False,
            filter_string=f"apply_overrides=0 min_qod=70 levels=hml task_id={task_id} rows=10000 sort=name",
        )

        rval = list()
        for result in results.findall("./result"):
            host = result.find("./host").text
            port_parts = result.find("./port").text.split("/", 1)
            if len(port_parts) == 1:
                proto = port_parts[0]
                port = 0
            else:
                port, proto = port_parts
                if port == "general":
                    port = 0
                else:
                    port = int(port)

            nvt = result.find("./nvt")
            vuln_name = nvt.find("./name").text
            oid = nvt.attrib["oid"]

            # cve
            cves = nvt.xpath('./refs/ref[@type="cve"]/@id')
            vuln_info = {
                "host_addr": host,
                "protocol": proto,
                "port": port,
                "oid": oid,
                "vuln_name": vuln_name,
                "cves": cves,
            }
            rval.append(vuln_info)

        set_progress(100)
        return rval


if __name__=="__main__":
    helper.start(main)