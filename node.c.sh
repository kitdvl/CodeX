#!/bin/bash

# cd /lib/systemd/system
# ln -s /usr/local/node/x32/node.c.service .
# systemctl status node.c.service
# systemctl daemon-reload
# systemctl enable node.c.service
# systemctl start node.c.service

/usr/local/node/x32/node.c.x32 --m console --d WAAS_NODE --s WAAS_NODE --X /usr/local/node/x32/code.X.x32.so --p /usr/local/node/x32/plugin --l /usr/local/node/log --e d7 -wssport 7810 -httpport 80 -home /usr/local/node/www -index index.html
