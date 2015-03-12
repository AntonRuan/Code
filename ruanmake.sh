make &&\
 cp res/res_pjsip_sync_ldap.so /opt/work/app/asterisk/lib/asterisk/modules/ &&\
 echo "asterisk -rx 'module unload res_pjsip_sync_ldap.so'" | nc 192.168.124.165 8900 &&\
 echo "asterisk -rx 'module load res_pjsip_sync_ldap.so'" | nc 192.168.124.165 8900
