make clean
make broker_connect.gb
goto-instrument broker_connect.gb broker_connect_new.gb \
    --generate-function-body '(?!__)str[a-zA-Z]*' --generate-function-body-options nondet-return \

cbmc broker_connect_new.gb --function mosquitto__connect_init --object-bits 63
# read -p "Press any key..."
# cbmc pub_new.gb --function init_config --malloc-may-fail --malloc-fail-null	--pointer-check
# read -p "Press any key..."
# cbmc pub_new.gb --function cfg_add_topic --malloc-may-fail --malloc-fail-null	--pointer-check
