# MC833-Projeto2

# ICMP (`analyzer.py`)

Este script foi criado para analisar arquivos `.pcap` contendo pacotes ICMP, capturados pela ferramenta **Wireshark**. Ele coleta dados estatísticos da comunicação de rede e gera gráficos que ajudam a entender o padrão de envio dos pacotes.

## 🔧 Funcionalidades

O programa realiza as seguintes operações:

- **Abertura de arquivos `.pcap`**: Analisa os arquivos padrão `H1-H3.pcap` e `H2-H4.pcap`.
- **Filtragem de pacotes**: Apenas pacotes do tipo **ICMP** são considerados.
- **Extração de métricas**:
  - IPs de origem e destino
  - Número total de pacotes ICMP
  - Volume total de dados (em bytes)
  - Throughput médio (bytes por segundo)
  - Intervalo médio entre os pacotes
- **Geração de gráficos**:
  - Variação do tamanho dos pacotes ao longo do tempo
  - Histograma dos intervalos entre pacotes
  - Gráfico do throughput por segundo

## 📦 Dependências

As bibliotecas necessárias estão listadas no arquivo `requirements.txt`. Para instalar tudo automaticamente, utilize o comando:

```bash
make install
```

## ▶️ Execução

Para rodar a análise:

```bash
make run
```

## 🧹 Limpeza

Para remover o ambiente virtual e os gráficos gerados:

```bash
make clean
```
