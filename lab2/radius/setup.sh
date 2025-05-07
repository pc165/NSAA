#!/bin/bash
cp /radius/clients.conf /etc/raddb/clients.conf
cp /radius/authorize /etc/raddb/mods-config/files/authorize
chmod 444 /etc/raddb/clients.conf
chmod 444 /etc/raddb/mods-config/files/authorize
cat /etc/raddb/clients.conf
cat /etc/raddb/mods-config/files/authorize
freeradius -X