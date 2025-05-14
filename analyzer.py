from scapy.all import rdpcap, IP
import matplotlib.pyplot as plt
import os

# Função para extrair dados úteis dos pacotes (timestamp, tamanho, IPs)
def extract_packet_data(packets):
    timestamps = []
    packet_sizes = []
    src_ips = []
    dst_ips = []

    for pkt in packets:
        if IP in pkt:  # só processa pacotes com camada IP
            timestamps.append(pkt.time)  # adiciona o tempo em que o pacote foi capturado
            packet_sizes.append(len(pkt))  # adiciona o tamanho do pacote
            src_ips.append(pkt[IP].src)  # adiciona o IP de origem
            dst_ips.append(pkt[IP].dst)  # adiciona o IP de destino

    return timestamps, packet_sizes, src_ips, dst_ips

# Função que calcula métricas úteis para análise de tráfego
def calculate_metrics(timestamps, packet_sizes):
    total_packets = len(packet_sizes) # total de pacotes capturados
    total_bytes = sum(packet_sizes)  # total de bytes capturados

    duration = timestamps[-1] - timestamps[0]  # tempo total da captura
    avg_throughput = total_bytes / duration if duration > 0 else 0 # throughput médio em bytes/s

    # cálculo dos tempos entre pacotes consecutivos
    inter_arrival_times = []
    for i in range(1, len(timestamps)):
        inter_arrival_times.append(timestamps[i] - timestamps[i - 1])

    avg_interval = sum(inter_arrival_times) / len(inter_arrival_times)

    return total_packets, avg_throughput, avg_interval, inter_arrival_times

# Função para calcular throughput por segundo (bytes/s)
def calculate_throughput_per_second(timestamps, packet_sizes):
    from collections import defaultdict
    import math
    throughput_dict = defaultdict(int)
    for i in range(len(timestamps)):
        t = timestamps[i]
        size = packet_sizes[i]
        t_seg = math.floor(t - timestamps[0])  # agrupar por segundo
        throughput_dict[t_seg] += size
    sorted_times = sorted(throughput_dict.keys())
    throughput_values = [throughput_dict[t] for t in sorted_times]
    return sorted_times, throughput_values

# Função para plotar o gráfico de throughput por segundo
def plot_throughput_per_second(file_path, base_name, sorted_times, throughput_values):
    plt.figure(figsize=(10, 6))
    plt.plot(sorted_times, throughput_values, marker='o', linestyle='-', color='red')
    plt.title(f"Throughput (por segundo) - {base_name}")
    plt.xlabel("Tempo (s)")
    plt.ylabel("Throughput (bytes/s)")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(f"{file_path}_throughput.png")
    plt.close()

# Função para imprimir as métricas de forma organizada
def print_metrics(file_path, total_packets, src_ips, dst_ips, avg_throughput, avg_interval):
    print("=" * 60)
    print(f"Arquivo analisado: {file_path}")
    print(f"Total de pacotes: {total_packets}")
    print(f"IPs de origem únicos: {sorted(set(src_ips))}")
    print(f"IPs de destino únicos: {sorted(set(dst_ips))}")
    print(f"Throughput médio: {avg_throughput:.2f} bytes/s")
    print(f"Intervalo médio entre pacotes: {avg_interval:.6f} s")
    print("=" * 60 + "\n")

# Geração de gráficos para visualização dos dados
def plot_graphs(file_path, timestamps, packet_sizes, inter_arrival_times):
    base_name = os.path.basename(file_path)

    # Gráfico de tamanho dos pacotes ao longo do tempo
    plt.figure(figsize=(10, 6))
    plt.plot(timestamps, packet_sizes, marker='o', linestyle='-', color='blue')
    plt.title(f"Tamanho dos Pacotes - {base_name}")
    plt.xlabel("Tempo (s)")
    plt.ylabel("Tamanho (bytes)")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(f"{file_path}_packet_sizes.png")
    plt.close()

    # Gráfico de intervalos entre pacotes
    plt.figure(figsize=(10, 6))
    plt.plot(inter_arrival_times, marker='x', linestyle='-', color='green')
    plt.title(f"Intervalos entre Pacotes - {base_name}")
    plt.xlabel("Índice do Pacote")
    plt.ylabel("Intervalo (s)")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(f"{file_path}_inter_arrival.png")
    plt.close()

    # Gráfico de throughput por segundo (bytes/s)
    sorted_times, throughput_values = calculate_throughput_per_second(timestamps, packet_sizes)
    plot_throughput_per_second(file_path, base_name, sorted_times, throughput_values)

    # Histograma dos tamanhos dos pacotes
    plt.figure(figsize=(10, 6))
    plt.hist(packet_sizes, bins=20, color='purple', edgecolor='black')
    plt.title(f"Histograma - Tamanhos dos Pacotes - {base_name}")
    plt.xlabel("Tamanho (bytes)")
    plt.ylabel("Frequência")
    plt.tight_layout()
    plt.savefig(f"{file_path}_size_hist.png")
    plt.close()

# Função principal que junta tudo
def analyze_pcap(file_path):
    print("")
    print(f"Analisando: {file_path}...")

    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"Erro ao abrir o arquivo {file_path}: {e}")
        return

    timestamps, packet_sizes, src_ips, dst_ips = extract_packet_data(packets)

    total_packets, avg_throughput, avg_interval, inter_arrival_times = calculate_metrics(timestamps, packet_sizes)

    print_metrics(file_path, total_packets, src_ips, dst_ips, avg_throughput, avg_interval)
    plot_graphs(file_path, timestamps, packet_sizes, inter_arrival_times)

# Ponto de entrada do script
if __name__ == "__main__":
    files = ["H1-H3.pcap", "H2-H4.pcap"]

    for file in files:
        analyze_pcap(file)
