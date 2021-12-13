make clean
make pub_client
goto-instrument pub.gb pub_new.gb --generate-function-body '(?!__)str[a-zA-Z]*' --generate-function-body-options nondet-return
cbmc pub_new.gb --function bar
read -p "Press any key..."
cbmc pub_new.gb --function init_config --malloc-may-fail --malloc-fail-null	--pointer-check
read -p "Press any key..."
cbmc pub_new.gb --function cfg_add_topic --malloc-may-fail --malloc-fail-null	--pointer-check
