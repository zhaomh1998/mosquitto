make clean
make broker_connect.gb
goto-instrument broker_connect.gb broker_connect_new.gb \
    --generate-function-body '(?!__)str[a-zA-Z]*' --generate-function-body-options nondet-return \

# cbmc broker_connect_new.gb --function mosquitto__connect_init --object-bits 63 \
#     --pointer-check --pointer-primitive-check --pointer-overflow-check \
#     --signed-overflow-check --unsigned-overflow-check --float-overflow-check \
#     --undefined-shift-check --nan-check \
#     --memory-leak-check --malloc-may-fail --malloc-fail-null
# read -p "Press any key..."

cbmc broker_connect_new.gb --function mosquitto__reconnect --object-bits 63 \
    --pointer-check --pointer-primitive-check --pointer-overflow-check \
    --signed-overflow-check --unsigned-overflow-check --float-overflow-check \
    --undefined-shift-check --nan-check \
    --memory-leak-check --malloc-may-fail --malloc-fail-null

# cbmc broker_connect_new.gb --function mosquitto_connect_bind_v5 --object-bits 63 \
#     --pointer-check --pointer-primitive-check --pointer-overflow-check \
#     --signed-overflow-check --unsigned-overflow-check --float-overflow-check \
#     --undefined-shift-check --nan-check \
#     --memory-leak-check --malloc-may-fail --malloc-fail-null
