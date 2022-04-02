# Grupo de Teleinformatica e Automacao (GTA, Coppe, UFRJ)
# Autor: Guilherme Araujo Thomaz
# Data da ultima modificacao: 05/01/2021
# Descrição: processa os dados coletados pelo script de medição

from fileinput import filename
import statistics as stats

def main():
    fileName = "./benchmark/insecure_publish_time.txt"
    f = open(fileName, 'r')
    round = 0
    clientes = [1, 10, 50, 100, 500, 700, 1000]
    listaVazoes = []
    listaTempos = []
    indiceCliente = 0
    print("Arquivo: "+fileName)
    for line in f.readlines():
        if (len(line) > 0):
            if (line[0] == 'I'):
                if (round == 100):
                    if indiceCliente == 0:
                        print("Tempo Clientes " + str(clientes[indiceCliente]) + " = " + \
                              str(stats.mean(listaTempos)) + " +- " + \
                              str((1.96/(10**0.5)) * stats.pstdev(listaTempos)))
                        print()
                    print("Vazao Clientes " + str(clientes[indiceCliente]) + " = " + \
                          str(stats.mean(listaVazoes)) + " +- " + \
                          str((1.96/(10**0.5)) * stats.pstdev(listaVazoes)))
                    listaVazoes = []
                    listaTempos = []
                    round = 1
                    indiceCliente += 1
                else:
                    round += 1
            elif (line[0] == 'S'):
                tempo_inicial = float(line[15:20]+'.'+line[21:30])
            elif (line[0] == 'F'):
                tempo_final = float(line[16:21]+'.'+line[22:31])
                delta_tempo = tempo_final - tempo_inicial
                listaTempos.append(delta_tempo)
                vazao = clientes[indiceCliente] / delta_tempo
                listaVazoes.append(vazao)
    if indiceCliente == 0:
        print("Tempo Clientes " + str(clientes[indiceCliente]) + " = " + \
              str(stats.mean(listaTempos)) + " +- " + \
              str((1.96/(10**0.5)) * stats.pstdev(listaTempos)))
        print()
    print("Vazao Clientes " + str(clientes[indiceCliente]) + " = " + \
          str(stats.mean(listaVazoes)) + " +- " + \
          str((1.96/(10**0.5)) * stats.pstdev(listaVazoes)))
    f.close()

if __name__ == "__main__":
    main()