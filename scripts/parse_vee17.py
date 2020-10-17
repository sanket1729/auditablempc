# Parse logs to create graphs

# Returns the time in nanosec
def parse_time(line):
    # Find the start index
    factor = 1
    end_ind = 4
    if line.endswith("ns\n"):
        factor = 1
    elif line.endswith("µs\n"):
        factor = 1000
    elif line.endswith("ms\n"):
        factor = 10 ** 6
    elif line.endswith("s\n"):
        end_ind = 3
        factor = 10 ** 9
    else:
        print(line)
        raise Exception("Invalid line")

    start_ind = -1
    first_dot = False
    for i in range(len(line) - end_ind, -1, -1):
        # print(line[i])
        if not line[i].isdigit():
            if not first_dot:
                first_dot = True
            else:
                start_ind = i + 1
                break

    t = line[start_ind : len(line) - end_ind + 1]
    t = float(t) * factor
    return t


def parse_int(line):
    return int(line.split(":")[1].strip())


class expr_res:
    def init_comm_time(self):
        print("imp" + str(self.init_partial_output_comm_time/10**9))
        return (
            self.init_partial_output_comm_time
            + self.init_commit_latency_combine_time
            + self.prover_init_time
        )

    def first_round_time(self):
        return (
            self.first_round_comm_time
            + self.first_round_latency
            + self.first_round_combine_time
        )

    def second_round_time(self):
        return (
            self.second_round_comm_time
            + self.second_round_latency
            + self.second_round_combine_time
        )

    def third_fourth_round_time(self):
        return (
            self.third_round_local_time
            + self.third_round_comm_time
            + self.fourth_round_local_time
            + self.fourth_round_comm_time
        )

    def pc_proof_time(self):
        return (
            self.pc_proof_init_time
            + self.pc_proof_create_time
            + self.local_eval_time / self.num_servers
            # + self.poly_eval_time/self.num_servers
            + self.eval_combine_time
            + self.local_prf_time
            + self.prf_combine_time
        )

    def total_prover_time(self):
        print("time " + str(self.init_comm_time()/10**9));
        print("time " + str(self.first_round_time()/10**9));
        print("time " + str(self.second_round_time()/10**9));
        print("time " + str(self.third_fourth_round_time()/10**9));
        return (
            self.init_comm_time()
            + self.first_round_time()
            + self.second_round_time()
            + self.third_fourth_round_time()
            + self.pc_proof_time()
        )

    def total_communication_cost(self):
        per_party_cost = (
            self.init_round_communication_cost
            + self.first_round_communication_cost
            + self.second_round_communication_cost
        )
        return self.num_servers * per_party_cost

    def auditor_time(self):
        return self.total_verify_time

    def __init__(self, filename):
        self.prover_init_time = 0
        self.init_partial_output_comm_time = 0
        self.first_round_comm_time = 0
        self.second_round_comm_time = 0
        self.init_round_communication_cost = 0
        self.local_eval_time = 0
        self.eval_combine_time = 0
        self.local_prf_time = 0
        with open(filename) as f:
            for i, line in enumerate(f.readlines()):
                if "statement length" in line:
                    self.stmt_len = int(line.split(":")[1].strip())
                elif "Number of constraints" in line:
                    self.num_constraints = int(line.split(":")[1].strip())
                elif "Number of servers" in line:
                    self.num_servers = int(line.split(":")[1].strip())
                elif "End:     KZG10::Setup" in line:
                    self.setup_time = parse_time(line)
                elif "End:     Marlin::Index " in line:
                    self.index_time = parse_time(line)
                if "End:     Computing Partial Commitments to output" in line:
                    self.init_partial_output_comm_time = max(
                        self.init_partial_output_comm_time, parse_time(line)
                    )
                elif "End:     Initial Commitment and Output Check time" in line:
                    self.init_commit_latency_combine_time = parse_time(line)
                elif "··End:     Initize prover for all servers" in line:
                    self.prover_init_time = max(self.prover_init_time, parse_time(line))
                elif "··End:     Committing to first round polys" in line:
                    self.first_round_comm_time = max(
                        self.first_round_comm_time, parse_time(line)
                    )
                elif "··End:     First Round communication" in line:
                    self.first_round_latency = parse_time(line)
                elif "··End:     Combining partial commitments" in line:
                    self.first_round_combine_time = parse_time(line)
                elif "··End:     Committing to second round polys" in line:
                    self.second_round_comm_time = max(
                        self.second_round_comm_time, parse_time(line)
                    )
                elif "··End:     Second Round communication" in line:
                    self.second_round_latency = parse_time(line)
                elif "··End:     Second Round Combine time" in line:
                    self.second_round_combine_time = parse_time(line)
                elif "··End:     AHP::Prover::ThirdRound" in line:
                    self.third_round_local_time = parse_time(line)
                elif "End:     Committing to third round polys" in line:
                    self.third_round_comm_time = parse_time(line)
                elif "··End:     AHP::Prover::FourthRound" in line:
                    self.fourth_round_local_time = parse_time(line)
                elif "··End:     Committing to fourth round polys" in line:
                    self.fourth_round_comm_time = parse_time(line)
                elif "··End:     PC proof init time" in line:
                    self.pc_proof_init_time = parse_time(line)
                elif "End:     Evaluating polynomials over query set" in line:
                    self.poly_eval_time = parse_time(line)
                elif "End:     PC Proof creation time" in line:
                    self.pc_proof_create_time = parse_time(line)
                elif "End:     Marlin::Verify" in line:
                    self.total_verify_time = parse_time(line)
                elif "End:     Check the statement time" in line:
                    self.stmt_only_verify_time = parse_time(line)
                # Communication related parsing.
                elif "Init Round Total Communication:" in line:
                    self.init_round_communication_cost += parse_int(line)
                elif "First round  Total shares size in bytes:" in line:
                    self.first_round_communication_cost = parse_int(line)
                elif "Second Round Total shares in bytes:" in line:
                    self.second_round_communication_cost = parse_int(line)
                elif "Argument size in bytes:" in line:
                    self.proof_size = parse_int(line)
                # More detail times
                elif "····End:     Combine evaluation" in line:
                    self.eval_combine_time += parse_time(line)
                elif "···End:     Local polynomial evaluation" in line:
                    self.local_eval_time += parse_time(line)
                elif "End:     Generating local Proof shares" in line:
                    self.local_prf_time = max(self.local_prf_time, parse_time(line))
                elif "End:     Combining MPC proofs!" in line:
                    self.prf_combine_time = parse_time(line)
                elif "End:     Auditer average time" in line:
                    self.auditer_avg_time = parse_time(line) / 10
                # TODO proofs parse


num_mpc_server_vec = [4]
num_clients_vec = [1, 7, 175]
num_bits_vec = [32]

import numpy as np
import matplotlib.pyplot as plt
import matplotlib


def plot_prover_time_vs_num_clients(plt, expr_dict, num_servers):
    import copy

    num_bits = num_bits_vec[0]
    x = np.array(num_clients_vec)
    y_vals = []
    for count in range(10):
        y = []
        x_new = []
        for i, x_elem in enumerate(x):
            if expr_dict[(num_bits, num_servers, x_elem, count)] is not None:
                print(x_elem, num_servers)
                y.append(
                    expr_dict[(num_bits, num_servers, x_elem, count)].total_prover_time() / 10 ** 9
                )
        y_vals.append(y)

    y_vals = np.array(y_vals)
    print(y_vals)

    errors_bar_y = 1.95*np.std(y_vals, axis = 0)/(len(y_vals)**0.5)

    print(errors_bar_y)
    y_vals_avg = np.average(y_vals, axis = 0)

    print(y_vals_avg)

    plt.minorticks_off()
    plt.errorbar(
        x,
        y_vals_avg,
        yerr = errors_bar_y,
        # marker=matplotlib.markers.CARETDOWNBASE,
        label=str(num_servers) + " servers",
    )


def plot_auditor_time_vs_stmt_len(plt, expr_dict, num_servers):
    import copy

    num_bits = num_bits_vec[0]
    x = np.array(num_clients_vec)
    y_vals = []
    for count in range(10):
        y = []
        x_new = []
        for i, x_elem in enumerate(x):
            if expr_dict[(num_bits, num_servers, x_elem, count)] is not None:
                print(x_elem, num_servers)
                y.append(
                    expr_dict[(num_bits, num_servers, x_elem, count)].auditer_avg_time / 10 ** 6
                )
        y_vals.append(y)

    y_vals = np.array(y_vals)

    errors_bar_y = 1.95*np.std(y_vals, axis = 0)/((len(y_vals)*10)**0.5)

    y_vals_avg = np.average(y_vals, axis = 0)
    print(y_vals)
    print(errors_bar_y)

    plt.minorticks_off()
    plt.errorbar(
        x,
        y_vals_avg,
        yerr = errors_bar_y,
        # marker=matplotlib.markers.CARETDOWNBASE,
        label=str(num_servers) + " servers",
    )


# def plot_proof_size_vs_stmt_len(plt, expr_dict, num_contraints):
# 	import copy

# 	num_server = 8
# 	x = np.array(stmt_len_vec)
# 	y = []
# 	x_new = []
# 	for i, x_elem in enumerate(x):
# 		if expr_dict[(num_server, num_contraints, x_elem)] is not None:
# 			# print(x_elem, num_contraints)
# 			y.append(expr_dict[(num_server, num_contraints, x_elem)].proof_size)
# 			x_new.append(x_elem)
# 	x, y = np.array(x_new), np.array(y)
# 	print(x, y)
# 	plt.minorticks_off()
# 	plt.plot(
# 		x,
# 		y,
# 		marker=matplotlib.markers.CARETDOWNBASE,
# 		label= "$2^{" + str((num_contraints.bit_length() - 1)) + "}$ constraints",
# 	)


# def plot_comm_cost_vs_stmt_len(plt, expr_dict, stmt_len):
# 	import copy

# 	num_contraints = 2**10
# 	x = np.array(num_mpc_server_vec)
# 	y = []
# 	x_new = []
# 	for i, x_elem in enumerate(x):
# 		if expr_dict[(x_elem, num_contraints, stmt_len)] is not None:
# 			# print(x_elem, num_contraints)
# 			y.append(expr_dict[(x_elem, num_contraints, stmt_len)].total_communication_cost()/2**20)
# 			x_new.append(x_elem)
# 	x, y = np.array(x_new), np.array(y)
# 	# print(x, y)
# 	plt.minorticks_off()
# 	plt.plot(
# 		x,
# 		y,
# 		marker=matplotlib.markers.CARETDOWNBASE,
# 		label= "$2^{" + str((stmt_len.bit_length() - 1)) + "}$ statement length",
# 	)


two_powers_text = ["$" + str(2) + "^{" + str(i) + "}$" for i in range(0, 21)]


if __name__ == "__main__":
    # run_name = "bench_run1oaj"
    run_name = "bench_run_vee17koj"

    expr_dict = dict()
    for i in range(10):
        for num_mpc_server in num_mpc_server_vec:
            for num_bits in num_bits_vec:
                for num_clients in num_clients_vec:
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
                        + str(i)
                        + ".txt"
                    )
                    try:
                        print(out_filename)
                        expr_dict[(num_bits, num_mpc_server, num_clients, i)] = expr_res(
                            out_filename
                        )
                    except FileNotFoundError:
                        expr_dict[(num_bits, num_mpc_server, num_clients, i)] = None
                    except:
                        raise

    # fig, ((ax1, ax2),(ax3, ax4)) = plt.subplots(2, 2)
    # fig = plt.figure()
    ax1 = plt.figure().add_subplot()
    ax2 = plt.figure().add_subplot()
    # ax3 = plt.figure().add_subplot()
    # ax4 = plt.figure().add_subplot()

    ax1.tick_params(axis='both', which='major', labelsize=11)
    ax2.tick_params(axis='both', which='major', labelsize=11)
    # ax3.tick_params(axis='both', which='major', labelsize=11)
    # ax4.tick_params(axis='both', which='major', labelsize=11)

    ax1.set_xscale("log")
    ax1.set_yscale("log")
    ax1.set_xlabel("Number of bids", fontsize = 14)
    ax1.set_ylabel("Prover time (s)", fontsize = 14)

    ax1.set_xticks(num_clients_vec)
    ax1.grid(True, linestyle = '--')
    ax1.set_xticklabels(two_powers_text[2 : 7 + 1])
    for num_servers in num_mpc_server_vec:
    	plot_prover_time_vs_num_clients(ax1, expr_dict, num_servers)
    ax1.legend(fontsize = 12)

    ax2.set_xscale("log")
    # ax2.set_yscale("log")
    ax2.set_xlabel("Number of bids", fontsize=14)
    ax2.set_ylabel("Auditor time (ms)", fontsize=14)

    ax2.grid(True, linestyle="--")
    ax2.set_xticks(num_clients_vec)
    ax2.set_xticklabels(two_powers_text[2 : 7 + 1])
    ax2.set_yticks(np.linspace(0, 100, 11, dtype="int"))
    ax2.set_ylim(0, 100)
    ax2.set_yticklabels(np.linspace(0, 100, 11, dtype="int"))
    for num_servers in num_mpc_server_vec:
        plot_auditor_time_vs_stmt_len(ax2, expr_dict, num_servers)
    ax2.legend(fontsize=12)

    # ax3.set_ylabel("Proof size(bytes)", fontsize = 14)
    # ax3.set_xlabel("length of statement $|X|$ (Group elements)", fontsize = 14)

    # ax3.grid(True, linestyle = '--')
    # ax3.set_xticks(stmt_len_vec)
    # ax3.set_xticklabels(two_powers_text[2 : 6 + 1])
    # for num_contraints in num_contraints_vec[::2]:
    # 	plot_proof_size_vs_stmt_len(ax3, expr_dict, num_contraints)
    # ax3.legend(fontsize = 12)

    # ax4.set_ylabel("Communication Cost(MegaBytes)", fontsize = 14)
    # ax4.set_xlabel("Number of MPC servers(n)", fontsize = 14)

    # ax4.grid(True, linestyle = '--')
    # ax4.set_xticks(num_mpc_server_vec)
    # ax4.set_xticklabels(two_powers_text[1 : 6 + 1])
    # for stmt_len in stmt_len_vec:
    # 	plot_comm_cost_vs_stmt_len(ax4, expr_dict, stmt_len)
    # ax4.legend(fontsize = 12)

    plt.show()
