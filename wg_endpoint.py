#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Reset wireguard endpoint. """
import logging
import sys

import fire
from wireguard import utils
from wireguard import wireguard

__author__ = "Guillaume Delpierre"
__credits__ = ["Guillaume Delpierre"]
__license__ = "GNU GPLv3"
__version__ = "0.1.0"
__maintainer__ = "Guillaume Delpierre"
__email__ = "github@llew.me"
__status__ = "Dev"


def handle_endpoint(interface_name, configuration_file):
    """

    :param interface_name:
    :param configuration_file:

    """
    wg = wireguard.Wireguard(interface_name)

    # as we use this script client-side, we only have to deal with one peer (master).
    wireguard_peer_conf = wireguard.convert(
        wireguard.ini_to_dict(configuration_file)
    ).get('peer')

    endpoint_vpn_addr = wireguard_peer_conf.get('AllowedIPs')[:-3]
    peer_name = wireguard_peer_conf.get('PublicKey')
    confs = {
        'preshared-key': wireguard_peer_conf.get('PresharedKey', None),
        'allowed-ips': wireguard_peer_conf.get('AllowedIPs', None),
        'endpoint': wireguard_peer_conf.get('Endpoint', None),
        'persistent-keepalive': wireguard_peer_conf.get('persistent_keepalive', None),
    }

    check_probe = utils.check_health_probe(
        endpoint_vpn_addr, interface=interface_name)

    if not check_probe:
        try:
            logging.info(f'Remove peer {peer_name}')
            wg.remove_peer(peer_name)
            logging.info(f'Set peer {peer_name}')
            wg.set_peer(interface_name, peer_name, **confs)
        except Exception as err:
            logging.critical(err)

    logging.info('Endpoint: OK')


if __name__ == '__main__':
    fire.Fire(handle_endpoint)
