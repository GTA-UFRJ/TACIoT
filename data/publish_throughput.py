# Grupo de Teleinformatica e Automacao (GTA, Coppe, UFRJ)
# Autor: Guilherme Araujo Thomaz
# Data da ultima modificacao: 05/01/2021
# Descrição: processa os dados coletados pelo script de medição

import statistics as stats

def main():
    f = open("./benchmark/publish_throughput.txt", 'r')
    round = 0
    clientes = [1, 10, 50, 100, 200, 500]
    listaVazoes = []
    listaTempos = []
    indiceCliente = 0
    for line in f.readlines():
        if (len(line) > 0):
            if (line[0] == 'I'):
                if (round == 10):
                    print("Vazao Clientes " + str(clientes[indiceCliente]) + " = " + \
                          str(stats.mean(listaVazoes)) + " +- " + \
                          str((1.96/(10**0.5)) * stats.pstdev(listaVazoes)))
                    print("Tempo Clientes " + str(clientes[indiceCliente]) + " = " + \
                          str(stats.mean(listaTempos)) + " +- " + \
                          str((1.96/(10**0.5)) * stats.pstdev(listaTempos)))
                    listaVazoes = []
                    listaTempos = []
                    round = 1
                    indiceCliente += 1
                else:
                    round += 1
            elif (line[0] == 'S'):
                tempo_inicial = float(line[18:20]+'.'+line[21:30])
            elif (line[0] == 'F'):
                tempo_final = float(line[19:21]+'.'+line[22:31])
                delta_tempo = tempo_final - tempo_inicial
                listaTempos.append(delta_tempo)
                vazao = clientes[indiceCliente] / delta_tempo
                listaVazoes.append(vazao)
    print("Vazao Cliente " + str(clientes[indiceCliente]) + " = " + \
            str(stats.mean(listaVazoes)) + " +- " + \
            str((1.96/(10**0.5)) * stats.pstdev(listaVazoes)))
    print("Tempo Clientes " + str(clientes[indiceCliente]) + " = " + \
          str(stats.mean(listaTempos)) + " +- " + \
          str((1.96/(10**0.5)) * stats.pstdev(listaTempos)))
    f.close()

if __name__ == "__main__":
    main()