# Grupo de Teleinformatica e Automacao (GTA, Coppe, UFRJ)
# Autor: Guilherme Araujo Thomaz
# Data da ultima modificacao: 31/12/2021
# Descrição: processa os dados coletados pelo script de medição

import statistics as stats

def main():
    f = open("./benchmark/register_time.txt", 'r')
    round = 0
    latencias = [1, 10, 50, 100]
    listaTempos = []
    indiceLatencia = 0
    for line in f.readlines():
        if (len(line) > 0):
            if (line[0] == 'I'):# or (round == 10 and indiceLatencia == 3):
                if (round == 10):
                    print("Latencia " + str(latencias[indiceLatencia]) + " = " + \
                          str(stats.mean(listaTempos)) + " +- " + \
                          str((1.96/10**0.5) * stats.pstdev(listaTempos)))
                    listaTempos = []
                    round = 1
                    indiceLatencia += 1
                else:
                    round += 1
            elif (line[0] == 'r'):
                tempo = float(line[7]+'.'+line[9:12])
                listaTempos.append(tempo)
    print("Latencia " + str(latencias[indiceLatencia]) + " = " + \
                        str(stats.mean(listaTempos)) + " +- " + \
                        str((1.96/10**0.5) * stats.pstdev(listaTempos)))
    f.close()

if __name__ == "__main__":
    main()