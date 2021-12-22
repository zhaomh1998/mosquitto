set -x
make clean
make $1.gb
goto-instrument $1.gb $1_new.gb \
    --generate-function-body '(?!__)str[a-zA-Z]*' --generate-function-body-options nondet-return \

#goto-instrument --dot $1.gb | tail -n +2 | dot -Tpng -Gdpi=1500 > $1.png

#cbmc handle_disconnect_new.gb --function handle__disconnect --object-bits 63 --pointer-check --bounds-check --div-by-zero-check --signed-overflow-check --undefined-shift-check --nan-check

cbmc $1_new.gb \
    --function $2 \
    --pointer-check \
    --bounds-check \
    --nan-check \
    --signed-overflow-check \
    --unwind 3 \
    --div-by-zero-check \
    --undefined-shift-check \
    --malloc-may-fail \
    --malloc-fail-null \
    --trace 
#    --no-assertions \

#read -p "Press any key..."
#cbmc pub_new.gb --function init_config --malloc-may-fail --malloc-fail-null	--pointer-check
#read -p "Press any key..."
#cbmc pub_new.gb --function cfg_add_topic --malloc-may-fail --malloc-fail-null	--pointer-check
##################END OF cbmc.sh######################
