import os
import random
import string


def randomString(stringLength=8):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(stringLength))


run_name = "bench_run_vee17" + randomString(3)
try:
    os.mkdir("./bench_logs/bench_logrank/" + run_name)
except:

    pass

num_mpc_server_vec = [4]
num_clients_vec = [1, 7, 175]
num_bits_vec = [32]

num_iter = 10
# num_mpc_server_vec = [4]
# num_clients_vec = [8]
# num_bits_vec = [32]


def run_rust_code(num_clients, num_mpc_server, num_bits, run_num):
    # NUM_CONSTRAINTS=105 NUM_SERVERS=4 STMT_LEN=16
    out_filename = (
        "./bench_logs/bench_logrank/"
        + run_name
        + "/params_"
        + str(num_bits)
        + "_"
        + str(num_mpc_server)
        + "_"
        + str(num_clients)
        + "_"
        + str(run_num)
        + ".txt"
    )
    cmd = (
        "NUM_BITS="
        + str(num_bits)
        + " NUM_SERVERS="
        + str(num_mpc_server)
        + " NUM_CLIENTS="
        + str(num_clients)
        + " cargo test --release --features=print-trace -- --nocapture bench_logrank > "
        + out_filename
    )
    os.system(cmd)


def multi_run_wrapper(args):
    return run_rust_code(*args)


def only_single_thread():
    for run_num in range(0,num_iter):
        for num_mpc_server in reversed(num_mpc_server_vec):
            for num_clients in num_clients_vec:
                for num_bits in num_bits_vec:
                    run_rust_code(num_clients, num_mpc_server, num_bits, run_num)


if __name__ == "__main__":
    # only_prover_graph_single_thread()
    only_single_thread()
    # only_verifier_graph_single_thread()
    # from multiprocessing import Pool

    # pool = Pool(processes=24)
    # small_args = []
    # medium_args = []
    # medium2_args = []
    # large_args = []
    # for num_mpc_server in reveresed(num_mpc_server_vec):
    # 	for num_contraints in num_contraints_vec:
    # 		for stmt in stmt_len_vec:
    # 			if num_contraints * num_mpc_server < 2 ** 21 + 1:
    # 				small_args.append((stmt, num_mpc_server, num_contraints))
    # 			elif num_contraints * num_mpc_server < 2 ** 23 + 1:
    # 				medium_args.append((stmt, num_mpc_server, num_contraints))
    # 			elif num_contraints * num_mpc_server < 2 ** 24 + 1:
    # 				medium2_args.append((stmt, num_mpc_server, num_contraints))
    # 			else:
    # 				large_args.append((stmt, num_mpc_server, num_contraints))
    # print(len(small_args))
    # print(len(medium_args))
    # print(len(medium2_args))
    # print(len(large_args))

    # # pool = Pool(processes=28)
    # # pool.map(multi_run_wrapper,small_args)
    # # pool = Pool(processes=8)
    # # pool.map(multi_run_wrapper,medium_args)
    # # pool = Pool(processes=4)
    # # pool.map(multi_run_wrapper,medium2_args)
    # # pool = Pool(processes=2)
    # # pool.map(multi_run_wrapper,large_args)
