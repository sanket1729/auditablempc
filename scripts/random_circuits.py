import os
import random
import string


def randomString(stringLength=8):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(stringLength))


# run_name = "bench_run1" + randomString(3)
run_name = "rand_logs"
try:
    os.mkdir("./bench_logs/pec/" + run_name)
except:

    pass

num_mpc_server_vec = [1, 2, 4, 8]
stmt_len_vec = [4, 8, 16, 32, 64]
num_contraints_vec = [2 ** i for i in range(10, 21)]

# stmt_len_vec = [4]
# num_mpc_server_vec = [4]
# num_contraints_vec = [100]


def run_rust_code(stmt_len, num_mpc_server, num_contraints, count):
    # NUM_CONSTRAINTS=105 NUM_SERVERS=4 STMT_LEN=16
    out_filename = (
        "./bench_logs/"
        + run_name
        + "/params_"
        + str(num_contraints)
        + "_"
        + str(num_mpc_server)
        + "_"
        + str(stmt_len)
        + "_"
        + str(count)
        + ".txt"
    )
    cmd = (
        "NUM_CONSTRAINTS="
        + str(num_contraints)
        + " NUM_SERVERS="
        + str(num_mpc_server)
        + " STMT_LEN="
        + str(stmt_len)
        + " cargo test --release --features=print-trace -- --nocapture bench_random > "
        + out_filename
    )
    os.system(cmd)


def multi_run_wrapper(args):
    return run_rust_code(*args)


def only_prover_graph_single_thread():
    for num_mpc_server in reversed(num_mpc_server_vec):
        for num_contraints in num_contraints_vec:
            for stmt in [8]:
                iter_count = 10
                if num_contraints > 2**18:
                    iter_count = 1
                elif num_contraints > 2**16:
                    iter_count = 3
                else:
                    iter_count = 10
                for c in range(0, iter_count):
                    run_rust_code(stmt, num_mpc_server, num_contraints, c)


def only_verifier_graph_single_thread():
    for num_mpc_server in [1]:
        for num_contraints in num_contraints_vec:
            for stmt in stmt_len_vec:
                iter_count = 10
                if num_contraints > 2**18:
                    iter_count = 1
                elif num_contraints > 2**16:
                    iter_count = 3
                else:
                    iter_count = 10
                for c in range(0, iter_count):
                    run_rust_code(stmt, 1, num_contraints, c)


if __name__ == "__main__":
    # only_prover_graph_single_thread()
    only_verifier_graph_single_thread()
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
