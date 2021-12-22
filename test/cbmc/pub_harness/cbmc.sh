make clean
make proof.gb
goto-instrument proof.gb proof_new.gb \
    --generate-function-body '(?!__)str[a-zA-Z]*' --generate-function-body-options nondet-return \
    # --remove-function-body 'packet__write'

cbmc proof_new.gb --function harness --pointer-check \
    --pointer-check --pointer-primitive-check --pointer-overflow-check \
    --signed-overflow-check --unsigned-overflow-check --float-overflow-check \
    --undefined-shift-check --nan-check \
    # --memory-leak-check --malloc-may-fail --malloc-fail-null --unwind 10

