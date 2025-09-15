# Tarea Corta 1 - ImageServer

Este proyecto implementa un demonio con el fin de brindar un servicio al usuario

## Compilar los programas

Primero asegurese de compilar los archivos antes de ejecutar 

```bash
gcc -o imageserver imageserver.c -lpthread -lm

gcc -o client client.c
```

## Ejecutar el servidor y el cliente

Para ejecutar el servidor y el cliente ejecute los siguientes comandos:

```bash
./imageserver.sh start

./client
```

## Cerrar cliente

Para cerrar el cliente solo digite el siguiente comando:

```bash
EXIT
```

## Detener servidor

Para detener el servidor solo digite el siguiente comando:

```bash
./imageserver.sh stop
```

## Otras acciones del servidos

Algunas de las otras acciones que puede hacer el servidor son las siguientes:

```bash
./imageserver.sh status     # Muestra el estado del servidor
```

```bash
./imageserver.sh restart    # Reinicia el servidor
```