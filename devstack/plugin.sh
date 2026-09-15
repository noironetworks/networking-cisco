#!/usr/bin/env bash

DIR_CISCO=$DEST/networking-cisco

if is_service_enabled net-cisco; then

    if [[ "$1" == "source" ]]; then
        :
    fi

    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        cd $DIR_CISCO
        echo "Installing Networking-Cisco"
        setup_develop $DIR_CISCO

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        if is_service_enabled q-ciscorouter && is_service_enabled ciscocfgagent; then
            source $DIR_CISCO/devstack/asr1k/cisco_neutron
            configure_cisco_asr1k_router
        fi

    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        if is_service_enabled q-ciscorouter && is_service_enabled ciscocfgagent; then
           net_start_neutron_agents
           start_cisco_asr1k_router
        fi
    fi

    if [[ "$1" == "unstack" ]]; then
        source $DIR_CISCO/devstack/asr1k/cisco_neutron
        net_stop_neutron

    fi

    if [[ "$1" == "clean" ]]; then
        :
    fi
fi
