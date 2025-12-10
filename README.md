# TrabalhoAssinadorDeMensagens

===================================================
Instruções para Execução do Assinador Digital
===================================================

Este programa foi desenvolvido em Python e por isso não requer a instalação de nenhuma biblioteca externa. Todos os módulos utilizados (os, struct, sys) fazem parte da biblioteca padrão (original) do Python.

O programa funciona perfeitamente no terminal PowerShell do Windows, não é necessário usar WSL.

---
COMO EXECUTAR
---

1. após baixar o arquivo assinador.py , copie o endereço do windows até ele.

2. Abra o PowerShell.

3. No PowerShell, digite o comando cd (endereço copiado para chegar no arquivo assinador.py).

4. Digite o seguinte comando:
   python assinador.py
   E pressione Enter. (Se o comando acima não funcionar, tente: python3 assinador.py)

5. O programa irá iniciar e mostrar um menu. A partir daí, basta seguir as instruções que o próprio programa apresenta na tela.

---
ROTEIRO DE TESTE
---
1. Execute o programa.
2. O programa dará instruções do que fazer.
2. Escolha a Opção 1 (Gerar Chaves).
3. Pressione [Enter] para usar os primos automáticos (recomendado) ou digite um número primo gigante de sua preferência.
4. Escolha a Opção 2 (Assinar Mensagem).
5. Digite uma mensagem (lembre dela) e pressione Enter.
6. O programa mostrará a "Assinatura Digital". Copie essa longa sequência de letras e números (hex).
7. Escolha a Opção 3 (Validar Assinatura).
8. Digite a *mesma* mensagem (que você decorou depois de escreve-la).
9. Cole a assinatura que você copiou no passo 6.
10. O programa deve exibir ">>> SUCESSO: A ASSINATURA É VÁLIDA! <<<".
11. Após isso, caso queira, pode sair do programa digitando a Opção 0.
