Os comandos devem ser executados a partir da raiz `/home/thr/Faculdade/TCC/ibr-etl`.

Parar:
```bash
touch datasets/rotacao_shodan_e3_full_20260919_103421/stop_shodan
```

Retomar:
```bash
other/shodan_rotation.sh -d datasets/e3_full -q 1000 -o datasets/rotacao_shodan_e3_full_20260919_103421/
```
