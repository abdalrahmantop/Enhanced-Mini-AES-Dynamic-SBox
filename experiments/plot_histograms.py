# experiments/plot_histograms.py
import matplotlib.pyplot as plt

from experiments.eval_avalanche_plaintext import run_plaintext_avalanche
from experiments.eval_key_sensitivity import run_key_sensitivity

def plot_hist(data_base, data_enh, title, out_path):
    # counts are 0..16
    bins = list(range(0, 18))  # 0..17 edges for 0..16 values
    plt.figure()
    plt.hist(data_base, bins=bins, alpha=0.7, label="Baseline")
    plt.hist(data_enh, bins=bins, alpha=0.7, label="Enhanced")
    plt.xlabel("Number of changed ciphertext bits (out of 16)")
    plt.ylabel("Frequency")
    plt.title(title)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=200)
    plt.close()

if __name__ == "__main__":
    _, _, base_p, enh_p = run_plaintext_avalanche(trials=5000)
    _, _, base_k, enh_k = run_key_sensitivity(trials=5000)

    plot_hist(base_p, enh_p, "Plaintext Avalanche Distribution (5000 trials)", "results/plots/plaintext_avalanche_hist.png")
    plot_hist(base_k, enh_k, "Key Sensitivity Distribution (5000 trials)", "results/plots/key_sensitivity_hist.png")

    print("Saved plots to:")
    print(" - results/plots/plaintext_avalanche_hist.png")
    print(" - results/plots/key_sensitivity_hist.png")
